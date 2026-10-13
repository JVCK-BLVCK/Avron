import json
import threading

from app import scanner


class FakeProcess:
    def __init__(self, output_lines=(), stderr_lines=(), returncode=0):
        self.stdout = iter(output_lines)
        self.stderr = iter(stderr_lines)
        self.returncode = returncode
        self.killed = False

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.killed = True


def test_run_nuclei_uses_pinned_target_and_persists_results(monkeypatch):
    finding = {"template-id": "example-template", "severity": "medium"}
    process = FakeProcess([json.dumps(finding) + "\n"])
    command = {}
    saved = []

    monkeypatch.setattr(
        scanner,
        "resolve_target_for_scan",
        lambda target: ("https://93.184.216.34/path", "example.com", "example.com", 4),
    )
    monkeypatch.setattr(scanner.subprocess, "Popen", lambda args, **kwargs: command.update(
        args=args, **kwargs
    ) or process)
    monkeypatch.setattr(scanner, "save_scan_sync", lambda scan_id, data: saved.append(data.copy()))

    scanner.run_nuclei("scan-1", "https://example.com/path")

    assert command["args"][command["args"].index("-u") + 1] == "https://93.184.216.34/path"
    assert "-disable-redirects" in command["args"]
    assert command["args"][command["args"].index("-H") + 1] == "Host: example.com"
    assert command["args"][command["args"].index("-sni") + 1] == "example.com"
    assert saved[1]["status"] == "in_progress"
    assert saved[-1]["status"] == "completed"
    assert saved[-1]["results"] == [finding]


def test_run_nuclei_fails_closed_when_worker_dns_validation_fails(monkeypatch):
    saved = []
    popen_calls = []

    def reject_target(_target):
        raise ValueError("target resolved to a private address")

    monkeypatch.setattr(scanner, "resolve_target_for_scan", reject_target)
    monkeypatch.setattr(scanner.subprocess, "Popen", lambda *args, **kwargs: popen_calls.append(args))
    monkeypatch.setattr(scanner, "save_scan_sync", lambda scan_id, data: saved.append(data.copy()))

    scanner.run_nuclei("scan-2", "https://example.com")

    assert not popen_calls
    assert saved[-1]["status"] == "failed"
    assert "public-address validation" in saved[-1]["error"]


def test_run_nuclei_records_process_failure(monkeypatch):
    process = FakeProcess(returncode=2, stderr_lines=["template error\n"])
    saved = []

    monkeypatch.setattr(
        scanner,
        "resolve_target_for_scan",
        lambda target: (target, None, None, 4),
    )
    monkeypatch.setattr(scanner.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(scanner, "save_scan_sync", lambda scan_id, data: saved.append(data.copy()))

    scanner.run_nuclei("scan-3", "https://example.com")

    assert saved[-1]["status"] == "failed"
    assert "exit code: 2" in saved[-1]["error"]


def test_run_nuclei_enforces_timeout_while_process_is_quiet(monkeypatch):
    stopped = threading.Event()

    class QuietOutput:
        def __iter__(self):
            return self

        def __next__(self):
            stopped.wait(timeout=2)
            if stopped.is_set():
                raise StopIteration
            raise StopIteration

    class QuietProcess(FakeProcess):
        def __init__(self):
            super().__init__()
            self.stdout = QuietOutput()

        def kill(self):
            self.killed = True
            stopped.set()

    process = QuietProcess()
    saved = []
    monkeypatch.setattr(scanner.settings, "scan_timeout_seconds", 0.05)
    monkeypatch.setattr(
        scanner,
        "resolve_target_for_scan",
        lambda target: (target, None, None, 4),
    )
    monkeypatch.setattr(scanner.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(scanner, "save_scan_sync", lambda scan_id, data: saved.append(data.copy()))

    scanner.run_nuclei("scan-4", "https://example.com")

    assert process.killed
    assert saved[-1]["status"] == "failed"
    assert "timed out" in saved[-1]["error"]
