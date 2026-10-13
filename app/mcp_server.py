"""
MCP server — exposes vulnerability scanner as AI-callable tools.

Six tools:
  scan_target        — submit URL for scanning, returns scan_id immediately
  get_scan_status    — check scan progress and retrieve findings
  get_scan_history   — all scans for a target over time
  analyse_findings   — enrich findings with NVD/EPSS data
  generate_report    — structured security report from findings
  compare_scans      — diff two scans to identify new/resolved issues
"""

import json
import logging
import uuid
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

from app.celery_worker import run_scan_task
from app.config import settings
from app.logging_config import setup_logging
from app.models import ScanRequest
from app.storage_db import (
    get_scans_by_target,
    load_scan,
    save_scan,
)


setup_logging(level=settings.log_level)
logger = logging.getLogger(__name__)

# Initialize the FastMCP application
mcp = FastMCP(
    "Avron",
    instructions="""Authorized web security scanner using Nuclei.

Core workflow:
    1. scan_target(url) → get scan_id immediately
    2. get_scan_status(scan_id) every 30s until completed or failed
    3. analyse_findings(scan_id) → enrich with CVSS + EPSS risk data
    4. generate_report(scan_id) → structured report for engineering team
    5. compare_scans(scan_id_a, scan_id_b) → identify what changed

History:
- get_scan_history(target) → all past scans for a target

Use analyse_findings to add optional CVSS/EPSS context before generating
a report. Enrichment depends on external NVD and FIRST services.

"""
)


@mcp.tool()
async def scan_target(target_url: str) -> str:
    """
    Submit a URL for vulnerability scanning. Returns immediately with a scan_id.

    Do NOT wait for completion here. After calling this tool, poll
    get_scan_status every 30 seconds until status is completed or failed.
    Scans typically take 2 to 10 minutes depending on target complexity.

    Args:
        target_url: The URL to scan. Must use http or https scheme.
    Returns:
        JSON with scan_id to use for polling get_scan_status.

    """
    try:
        validated = ScanRequest(target_url=target_url)
    except Exception as e:
        return json.dumps({"error": "Invalid URL", "detail": str(e)})

    scan_id = str(uuid.uuid4())
    started = datetime.now(timezone.utc)

    logger.info({
        "event":     "mcp_scan_requested",
        "scan_id":   scan_id,
        "target":    validated.target_url,
        "timestamp": started.isoformat()
    })

    # Save initial scan record with status "in_progress" so get_scan_status can return meaningful data immediately,
    # even if the scan is still running.
    initial_data = {
        "scan_id":   scan_id,
        "target":    validated.target_url,
        "status":    "in_progress",
        "timestamp": started.isoformat(),
        "error":     None,
        "results":   [],
    }
    try:
        await save_scan(scan_id, initial_data)
        # Use the same durable worker queue as the REST API. The MCP process
        # returns promptly while Celery owns the scan lifecycle.
        run_scan_task.apply_async(
            args=[scan_id, validated.target_url],
            task_id=scan_id,
        )
    except Exception:
        logger.exception("mcp_scan_queue_failed", extra={"scan_id": scan_id})
        failed_data = {
            **initial_data,
            "status": "failed",
            "error": "Scan could not be queued. Check the worker and Redis service.",
        }
        try:
            await save_scan(scan_id, failed_data)
        except Exception:
            logger.exception("mcp_scan_failure_status_save_failed", extra={"scan_id": scan_id})
        return json.dumps({"error": failed_data["error"], "scan_id": scan_id})

    logger.info({
        "event":    "mcp_scan_queued",
        "scan_id":   scan_id,
        "target":    validated.target_url,
    })

    # Return immediately -scan is running in background, client should poll get_scan_status for updates
    return json.dumps({
        "scan_id": scan_id,
        "status":  "in_progress",
        "message": "Scan started. Poll get_scan_status every 30 seconds until status is completed or failed.",
        "target":  validated.target_url,
        "started_at": started.isoformat()
    })

@mcp.tool()
async def get_scan_status(scan_id: str) -> str:
    """
    Retrieve current status and results for an existing scan either running or completed.

    Args:
        scan_id: The scan_id returned by scan_target.

    Returns:
        JSON string with current scan status, findings_count and any findings list when completed.
        If scan_id is unknown, returns error message. Always returns valid JSON.

    """
    if not scan_id:
        return json.dumps({"error": "scan_id is required"})

    try:
        data = await load_scan(scan_id)
    except IOError as e:
        return json.dumps({"error": f"Storage error: {str(e)}"})

    if data is None:
        return json.dumps({"error": "Scan not found", "scan_id": scan_id})

    status = data["status"]

    # Build a response that gives Claude everything it needs to decide what to do next:
    # Whether to keep polling, or if completed, how many findings and what they are.
    # This allows Claude to make informed decisions about whether to wait,
    # ask the user for more info, or report results, without needing to call additional tools or ask follow-up questions.
    response ={
        "scan_id":        data["scan_id"],
        "target":         data.get("target"),
        "status":         status,
        "findings_count": len(data.get("results", [])),
        "findings":       data.get("results", []),
        "error":          data.get("error"),
        "timestamp":      data.get("timestamp")
    }

    if status == "in_progress":
        response["message"] = "Scan is still running. Please check back later for results." \
        "Poll again in 30 seconds or so. " \
        "If the scan is taking significantly longer than expected, there may be an issue with the target or the scanning process."

    elif status == "completed":
        response["findings"] = data.get("results", [])
        response["message"] = (
            f"Scan completed. Found {response['findings_count']} vulnerabilities. "
            if response["findings_count"] > 0
            else "Scan completed. No vulnerabilities found."

        )

    elif status == "failed":
        response["error"] = data.get("error")
        response["message"] = f"Scan failed: {data.get('error')}"

    return json.dumps(response, indent=2)


@mcp.tool()
async def get_scan_history(target_url: str, limit: int = 10) -> str:
    """
        Retrieve all past scans for a target URL.

        Use this to identify vulnerability trends, regressions, and
        whether previously found issues have been remediated.

        Args:
            target_url: The URL to fetch history for.
            limit:      Maximum number of scans to return (default 10).

        Returns:
            JSON with list of scans ordered most-recent-first.
    """
    if not target_url:
        return json.dumps({"error": "target_url is required"})

    try:
        scans = await get_scans_by_target(target_url, limit=limit)
    except IOError as e:
        return json.dumps({"error": f"Storage error: {str(e)}"})

    if not scans:
        return json.dumps({
            "target":  target_url,
            "message": "No scan history found for this target.",
            "scans":   []
        })

    # Summarise each scan without returning full findings (can be large)
    summaries = [{
        "scan_id":        s["scan_id"],
        "status":         s["status"],
        "timestamp":      s["timestamp"],
        "findings_count": len(s.get("results", [])),
        "error":          s.get("error"),
        "severity_breakdown": _severity_breakdown(s.get("results", []))
    } for s in scans]

    return json.dumps({
        "target":       target_url,
        "total_scans":  len(summaries),
        "scans":        summaries,
        "trend":        _history_trend(summaries),
        "message": (
            f"Found {len(summaries)} scan(s) for {target_url}. "
            f"Use compare_scans(oldest_scan_id, newest_scan_id) "
            f"to see what changed."
        )
    }, indent=2)

@mcp.tool()
async def analyse_findings(scan_id: str) -> str:
    """
    Enrich scan findings with CVSS severity scores and EPSS exploitation
    probability from NVD and FIRST.org.

    CVSS measures theoretical severity (impact if exploited).
    EPSS measures practical risk (probability of exploitation in next 30 days).
    Together they identify which vulnerabilities need immediate action.

    Args:
        scan_id: The completed scan to analyse.

    Returns:
        JSON with enriched findings sorted by risk priority.
    """
    try:
        data = await load_scan(scan_id)
    except IOError as e:
        return json.dumps({"error": f"Storage error: {str(e)}"})

    if data is None:
        return json.dumps({"error": "Scan not found", "scan_id": scan_id})

    if data["status"] != "completed":
        return json.dumps({
            "error":  "Scan not complete",
            "status": data["status"],
            "message": "Wait for scan completion before analysing findings."
        })

    findings = data.get("results", [])
    if not findings:
        return json.dumps({
            "scan_id":  scan_id,
            "message":  "No findings to analyse.",
            "findings": []
        })

    # Enrich findings concurrently
    from app.enrichment import enrich_findings
    enriched = await enrich_findings(findings)

    # Sort by risk_priority (higher = more urgent)
    enriched_sorted = sorted(
        enriched,
        key=lambda f: -(f.get("enrichment", {}).get("risk_priority", 0))
    )

    # Count active threats
    active_threats = sum(
        1 for f in enriched
        if f.get("enrichment", {}).get("epss_score", 0) > 0.1
    )

    return json.dumps({
        "scan_id":        scan_id,
        "target":         data.get("target"),
        "total_findings": len(findings),
        "active_threats": active_threats,
        "message": (
            f"{active_threats} finding(s) with active exploitation detected. "
            f"Use generate_report for full remediation guidance."
            if active_threats > 0
            else "No actively exploited vulnerabilities detected. "
                 "Use generate_report for full remediation guidance."
        ),
        "enriched_findings": enriched_sorted
    }, indent=2)


@mcp.tool()
async def generate_report(
    scan_id: str,
    include_enrichment: bool = True
) -> str:
    """
    Generate a structured security report from scan findings.

    The report includes executive summary, risk rating, prioritised
    remediation list, and finding details. Suitable for sharing
    directly with engineering teams.

    Args:
        scan_id:            The completed scan to report on.
        include_enrichment: Whether to fetch NVD/EPSS data (default True).
                           Set False for faster reports without risk scoring.

    Returns:
        JSON security report with executive summary and remediation priorities.
    """
    try:
        data = await load_scan(scan_id)
    except IOError as e:
        return json.dumps({"error": f"Storage error: {str(e)}"})

    if data is None:
        return json.dumps({"error": "Scan not found", "scan_id": scan_id})

    if data["status"] != "completed":
        return json.dumps({
            "error":  "Scan not complete",
            "status": data["status"]
        })

    enriched_findings = None
    if include_enrichment and data.get("results"):
        from app.enrichment import enrich_findings
        enriched_findings = await enrich_findings(data["results"])

    from app.report import generate_report as _generate_report
    report = _generate_report(data, enriched_findings)

    return json.dumps(report, indent=2)


@mcp.tool()
async def compare_scans(
    baseline_scan_id: str,
    current_scan_id:  str
) -> str:
    """
    Compare two scans of the same target to identify changes.

    Shows:
    - New findings (vulnerabilities introduced since baseline)
    - Resolved findings (vulnerabilities that no longer appear)
    - Persistent findings (vulnerabilities present in both scans)
    - Security trend (IMPROVING / DEGRADING / STABLE)

    Args:
        baseline_scan_id: The earlier scan (point of comparison).
        current_scan_id:  The later scan (current state).

    Returns:
        JSON diff with new, resolved, and persistent findings.
    """
    try:
        baseline = await load_scan(baseline_scan_id)
        current  = await load_scan(current_scan_id)
    except IOError as e:
        return json.dumps({"error": f"Storage error: {str(e)}"})

    if baseline is None:
        return json.dumps({
            "error":   "Baseline scan not found",
            "scan_id": baseline_scan_id
        })
    if current is None:
        return json.dumps({
            "error":   "Current scan not found",
            "scan_id": current_scan_id
        })

    if baseline["status"] != "completed" or current["status"] != "completed":
        return json.dumps({
            "error": "Both scans must be completed before comparison",
            "baseline_status": baseline["status"],
            "current_status":  current["status"]
        })

    if baseline.get("target") != current.get("target"):
        return json.dumps({
            "error": "Scans target different URLs — comparison would be misleading",
            "baseline_target": baseline.get("target"),
            "current_target":  current.get("target")
        })

    from app.report import compare_scans as _compare_scans
    comparison = _compare_scans(baseline, current)

    return json.dumps(comparison, indent=2)


# ─── Helper functions ─────────────────────────────────────────────────────────

def _severity_breakdown(findings: list) -> dict:
    """Count findings by severity."""
    breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev in breakdown:
            breakdown[sev] += 1
    return breakdown


def _history_trend(summaries: list) -> str:
    """Determine security trend from scan history."""
    if len(summaries) < 2:
        return "INSUFFICIENT_DATA"
    latest   = summaries[0]["findings_count"]
    previous = summaries[1]["findings_count"]
    if latest < previous:
        return "IMPROVING"
    if latest > previous:
        return "DEGRADING"
    return "STABLE"


if __name__ == "__main__":
    mcp.run()
