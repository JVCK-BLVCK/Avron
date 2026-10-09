"""Prometheus metrics for Avron's REST scanning workflow."""
from prometheus_client import Counter, Gauge, Histogram

# ___Scan lifecycle counters___

SCANS_TOTAL = Counter(
    "avron_scans_total",
    "Total number of scans submitted",
    ["status"]   # label: completed, failed, timeout
)

SCANS_ACTIVE = Gauge(
    "avron_scans_active",
    "Number of scans currently running"
)

# ___Scan Duration___
#
# Histogram buckets define the resolution of duration tracking.
# These buckets cover 1s, 30s, 1min, 2min, 5min, 10min — the realistic
# range for Nuclei scan durations.

SCAN_DURATION = Histogram(
    "avron_scan_duration_seconds",
    "Duration of Nuclei scans in seconds",
    buckets=[1, 5, 15, 30, 60, 120, 300, 600]
)

# ___Finding statistics___

FINDINGS_TOTAL = Counter(
    "avron_findings_total",
    "Total vulnerability findings discovered",
    ["severity"]   # label: critical, high, medium, low, info
)

