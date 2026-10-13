"Nuclei Execution Logic"
import json
import logging
import queue
import subprocess
import sys
import threading
import time

from app.metrics import (
    SCANS_TOTAL, SCAN_DURATION, SCANS_ACTIVE, FINDINGS_TOTAL
)
from datetime import datetime, timezone
from app.storage_db import save_scan_sync   # sync writer — no asyncio.run()
from app.models import resolve_target_for_scan
from app.config import settings


logger = logging.getLogger(__name__)


def run_nuclei(scan_id: str, target_url: str):
    """Execute Nuclei scanner, stream results into storage and save them as they arrive."""

    started = datetime.now(timezone.utc)
    status = "failed"
    error = None
    results: list = []
    proc = None       # explicit None so the TimeoutExpired handler never hits NameError if proc is referenced before assignment

    # Re-resolve in the worker because a queued task may run after DNS changes.
    # Pinning the result below also prevents another lookup between validation
    # and Nuclei's connection attempt.
    try:
        nuclei_target, host_header, tls_sni, ip_version = resolve_target_for_scan(target_url)
    except ValueError as exc:
        error = "Target failed public-address validation immediately before scanning"
        logger.warning(json.dumps({
            "event": "scan_target_rejected_on_worker",
            "scan_id": scan_id,
            "target": target_url,
            "reason": str(exc),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }))
        SCANS_TOTAL.labels(status="failed").inc()
        SCAN_DURATION.observe((datetime.now(timezone.utc) - started).total_seconds())
        save_scan_sync(scan_id, {
            "scan_id": scan_id,
            "target": target_url,
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": error,
            "results": results,
        })
        return

    # Increment active scans
    SCANS_ACTIVE.inc()
    status = "in_progress"
    
    logger.info(json.dumps({
        "event": "nuclei_scan_started",
        "scan_id": scan_id,
        "target": target_url,
        "timestamp": started.isoformat()
    }))

    # Write "in_progress" immediately -scan_target already wrote it, but this
    # acts as a confirmation that the thread actually started.
    save_scan_sync(scan_id, {
        "scan_id": scan_id,
        "target": target_url,
        "status": "in_progress",
        "timestamp": started.isoformat(),
        "error": None,
        "results": [],

    })


    command = [
        "nuclei",
        "-u", nuclei_target,
        "-jsonl",
        "-rate-limit", "10",     # max 10 requests/sec (default is 150)
        "-timeout", "10",        # per-request timeout in seconds
        "-retries", "1",         # retry once before marking unresponsive
        "-c", "2",               # max 2 concurrent templates
        "-severity", "info,low,medium,high,critical",
        "-exclude", "CVE-2023-2986.yaml,CVE-2024-9487.yaml",
        "-nmhe",
        "-no-interactsh",
        # A redirect could move the scan to a hostname/IP that did not pass the
        # public-address check, so keep Nuclei on the validated destination.
        "-disable-redirects",
        "-exclude-tags", "sqli,sql,sql-injection,injection,blind,time-based,sleep,dos,fuzz,wordpress,wp,ssti,ssrf,oast,xxe,pmpro,apache,lfi,woocommerce",
        "-exclude-type", "code",
        "-disable-unsigned-templates",  
    ]

    command.extend(["-ip-version", str(ip_version)])
    if host_header:
        # The socket target is the pinned IP, while Host/SNI keep the intended
        # DNS virtual host selected at the HTTP and TLS layers.
        command.extend(["-H", f"Host: {host_header}"])
    if tls_sni:
        command.extend(["-sni", tls_sni])

    
    try: 
        proc = subprocess.Popen(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        )

        # Guard against environments where subprocess.Pipe objects are missing or
        # returned as None. Iterating proc.stdout directly causes the exact
        # 'Object of type "None" cannot be used as an iterable value' style failure.
        if proc.stdout is None:
            error = "Nuclei process did not expose an stdout pipe"
            logger.error(json.dumps({
                "event": "nuclei_stdout_missing",
                "scan_id": scan_id,
                "target": target_url,
                "status": status,
                "error": error,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }))
            proc.kill()
            proc.wait()
            raise RuntimeError(error)

        # Drain stderr in a separate thread to prevent blocking if Nuclei produces a lot of output.
        # Only start the thread when the stderr pipe exists.
        stderr_lines: list[str] = []
        stderr_thread = None

        def _drain_stderr(pipe):
            for line in pipe:
                stderr_lines.append(line)

        if proc.stderr is not None:
            stderr_thread = threading.Thread(target=_drain_stderr, args=(proc.stderr,), daemon=True)
            stderr_thread.start()


        # Read output on a helper thread so the timeout also applies while
        # Nuclei is quiet. Iterating a subprocess pipe directly can block
        # forever before the next output line arrives.
        stdout_queue: queue.Queue[str | object] = queue.Queue()
        stdout_done = object()

        def _read_stdout(pipe):
            try:
                for output_line in pipe:
                    stdout_queue.put(output_line)
            finally:
                stdout_queue.put(stdout_done)

        stdout_thread = threading.Thread(
            target=_read_stdout,
            args=(proc.stdout,),
            daemon=True,
        )
        stdout_thread.start()
        deadline = time.monotonic() + settings.scan_timeout_seconds

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                proc.kill()
                status = "failed"
                error = f"Nuclei scan timed out after {settings.scan_timeout_seconds} seconds"
                logger.error(json.dumps({
                    "event": "scan_timeout",
                    "scan_id": scan_id,
                    "target": target_url,
                    "status": status,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }))
                break

            try:
                raw_line = stdout_queue.get(timeout=min(remaining, 0.25))
            except queue.Empty:
                continue

            if raw_line is stdout_done:
                break

            line = str(raw_line).strip()
            if not line:
                continue

            try:
                finding = json.loads(line)
                results.append(finding)

                # Increment findings total based on severity
                severity = finding.get("severity", "info").lower()
                FINDINGS_TOTAL.labels(severity=severity).inc()

                # synchronous atomic write - safe from any thread
                save_scan_sync(scan_id, {
                    "scan_id": scan_id,
                    "target": target_url,
                    "status": status,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "error": None,
                    "results": results,
                })

            except json.JSONDecodeError:
                logger.warning(json.dumps({
                    "event": "invalid_json_line",
                    "scan_id": scan_id,
                    "target": target_url,
                    "line": line,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }))

        # ___END STREAMING LOOP___

        try:
            proc.wait(timeout=max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            status = "failed"
            error = f"Nuclei scan timed out after {settings.scan_timeout_seconds} seconds"
        stdout_thread.join(timeout=5)
        if stderr_thread is not None:
            stderr_thread.join(timeout=5)
        stderr = "".join(stderr_lines)

        if error is None: 
            if proc.returncode != 0:
                raise subprocess.CalledProcessError(proc.returncode, command, "", stderr)
            
            status = "completed"

            # Increment completed scans
            SCANS_TOTAL.labels(status="completed").inc()

        if stderr:
            logger.warning(json.dumps({
                "event": "nuclei_stderr_output",
                "scan_id": scan_id,
                "target": target_url,
                "status": status,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "stderr": stderr
            }))


    except subprocess.CalledProcessError as e:
        status = "failed"
        error = f"Nuclei scan failed with exit code: {e.returncode}"
        logger.error(json.dumps({
            "event": "scan_process_failed",
            "scan_id": scan_id,
            "target": target_url,
            "status": status,
            "returncode": e.returncode,
            "stderr": e.stderr,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }))

        # Increment failed scans
        SCANS_TOTAL.labels(status="failed").inc()
    
    except FileNotFoundError:
        status = "failed"
        error = "Nuclei not found in system PATH"
        logger.error(json.dumps({
            "event": "nuclei_not_found",
            "scan_id": scan_id,
            "target": target_url,
            "status": status,
            "error": error,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }))

        # Increment failed scans
        SCANS_TOTAL.labels(status="failed").inc()

    except Exception:
        status = "failed"
        error = "Nuclei scan failed due to an internal error"
        logger.exception("nuclei_scan_unexpected_error", extra={"scan_id": scan_id})
        raise

    finally:

        # Calculate and observe scan duration
        duration = (datetime.now(timezone.utc) - started).total_seconds()
        SCAN_DURATION.observe(duration)


        # Write terminal state -synchronous, same as above 
        save_scan_sync(scan_id, {
            "scan_id":   scan_id,
            "target":    target_url,
            "status":    status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error":     error,
            "results":   results,
        })

        logger.info(json.dumps({
            "event": "nuclei_scan_finished",
            "scan_id": scan_id,
            "target": target_url,
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": error
        }))

        # Decrement active scans
        SCANS_ACTIVE.dec()

