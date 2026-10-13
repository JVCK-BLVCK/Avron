"""
Security report generation from scan findings.

Transforms raw Nuclei findings into structured reports that engineering
teams can act on directly. The report format is designed for:
  1. Triage — what needs fixing immediately vs what can wait
  2. Communication — what does the engineering team need to know
  3. Tracking — what changed since last scan

Why generate reports programmatically?
Security teams spend significant time manually writing reports from
scanner output. This is exactly the kind of structured transformation
AI agents excel at — pattern recognition + structured output.
The report format is designed so an AI agent can generate the
executive summary, remediation steps, and priority ordering
without human intervention.

"""
from datetime import datetime, timezone
from typing import Optional, Dict, Any


SEVERITY_ORDER = {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4,
    "info": 5,
    "unknown": 6,
}


def generate_report(
        scan_data: dict,
        enriched_findings: Optional[list] = None,
        report_format: str = "json"
    ) -> Dict[str, Any]:
    """
        Generate a structured security report from a completed scan.

    Args:
        scan_data:          The scan dict from storage (scan_id, target, results...)
        enriched_findings:  Optional enriched findings from enrich_findings().
                           If None, uses raw findings from scan_data.

    Returns:
        A structured report dict ready for JSON serialisation or
        agent consumption.
        """
    findings = enriched_findings or scan_data.get("results", [])
    target = scan_data.get("target", "unknown")
    scan_id = scan_data.get("scan_id", "unknown")

    # Sort findings by severity using SEVERITY_ORDER mapping
    by_severity: dict[str, list] = {}
    for finding in findings:
        severity = finding.get("severity", "unknown").lower()
        if severity not in by_severity:
            by_severity[severity] = []
        by_severity[severity].append(finding)

    # Create a sorted list of findings based on severity
    sorted_groups = sorted(
        by_severity.items(),
        key=lambda x: SEVERITY_ORDER.get(x[0], 99)
    )

    # Compute summary statistics
    total       = len(findings)
    critical    = len(by_severity.get("critical", []))
    high        = len(by_severity.get("high", []))
    medium      = len(by_severity.get("medium", []))
    low         = len(by_severity.get("low", []))
    info        = len(by_severity.get("info", []))

    # Determine the overall severity of the scan based on the highest severity finding
    if critical > 0:
        risk_rating = "CRITICAL"
    elif high > 0:
        risk_rating = "HIGH"
    elif medium > 0:
        risk_rating = "MEDIUM"
    elif low > 0:
        risk_rating = "LOW"
    else:
        risk_rating = "CLEAN"

    # Identify immediately actionable findings (critical or high severity)
    # These are the findings that should be prioritized for remediation.
    immediate_action = [
        f for f in findings
        if f.get("severity", "").lower() == "critical"
        or f.get("enrichment", {}).get("epss_score", 0) > 0.1
    ]

    # Build the report
    report = {
        "report_id":       f"report-{scan_id[:8]}",
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "scan_id":         scan_id,
        "target":          target,
        "scan_timestamp":  scan_data.get("timestamp"),

        "executive_summary": {
            "risk_rating":      risk_rating,
            "total_findings":   total,
            "requires_immediate_action": len(immediate_action) > 0,
            "breakdown": {
                "critical": critical,
                "high":     high,
                "medium":   medium,
                "low":      low,
                "info":     info
            }
        },

        "immediate_action_required": [
            _format_finding_for_report(f) for f in immediate_action
        ],

        "findings_by_severity": {
            severity: [_format_finding_for_report(f) for f in group_findings]
            for severity, group_findings in sorted_groups
        },

        "remediation_priorities": _generate_remediation_priorities(
            findings, enriched_findings is not None
        ),

        "raw_findings_count": total
    }

    return report

def _format_finding_for_report(finding: dict) -> dict:
    """
        Format a single finding for report inclusion
    """
    enrichment = finding.get("enrichment", {})
    return {
        "template_id":   finding.get("template-id", "unknown"),
        "name":          finding.get("name", finding.get("template-id", "unknown")),
        "severity":      finding.get("severity", "unknown"),
        "host":          finding.get("host", ""),
        "matched_at":    finding.get("matched-at", finding.get("host", "")),
        "description":   enrichment.get("description", ""),
        "cvss_score":    enrichment.get("cvss_score"),
        "epss_score":    enrichment.get("epss_score"),
        "epss_label":    _epss_label(enrichment.get("epss_score")),
        "has_patch":     enrichment.get("has_patch"),
        "cwe_ids":       enrichment.get("cwe_ids", []),
        "nvd_url":       enrichment.get("nvd_url", ""),
        "risk_priority": enrichment.get("risk_priority"),
        "risk_label":    enrichment.get("risk_label", ""),
    }

def _epss_label(epss_score: Optional[float]) -> str:
    """Convert EPSS score to human-readable exploitation Likelihood."""
    if epss_score is None:
        return "unknown"
    if epss_score >= 0.5:
        return "actively exploited"
    if epss_score >= 0.1:
        return "exploitation likely"
    if epss_score >= 0.01:
        return "exploitation possible"
    return "exploitation unlikely"


def _generate_remediation_priorities(
        findings: list,
        is_enriched: bool
) -> list[dict]:
    """
    Generate a prioritised remediation list.

    Priority order:
      1. Critical + actively exploited (CVSS >= 9 AND EPSS >= 0.5)
      2. Critical severity
      3. High + actively exploited
      4. High severity
      5. Medium + actively exploited
      6. Everything else

    This order reflects real security operations practice — a critical
    vulnerability with active exploitation must be patched today,
    not this sprint.

    """
    priorities = []

    def priority_key(f):
        severity = f.get("severity", "unknown").lower()
        epss = f.get("enrichment", {}).get("epss_score", 0) if is_enriched else 0
        cvss = f.get("enrichment", {}).get("cvss_score", 0) if is_enriched else 0


        sev_order = SEVERITY_ORDER.get(severity, 99)
        # Negative EPSS so higher EPSS = lower sort key = higher priority
        return (sev_order, -epss, -cvss)

    sorted_findings = sorted(findings, key=priority_key)

    for i, finding in enumerate(sorted_findings[:20], 1): # top 20
        enrichment = finding.get("enrichment", {}) if is_enriched else {}
        priorities.append({
            "priority":    i,
            "template_id": finding.get("template-id", "unknown"),
            "severity":    finding.get("severity", "unknown"),
            "cvss_score":  enrichment.get("cvss_score"),
            "epss_score":  enrichment.get("epss_score"),
            "epss_label":  _epss_label(enrichment.get("epss_score")),
            "has_patch":   enrichment.get("has_patch"),
            "action":      _remediation_action(finding, enrichment)
        })

    return priorities

def _remediation_action(finding: dict, enrichment: dict) -> str:
    """Generate a specific remediation action string."""
    severity = finding.get("severity", "unknown").lower()
    epss     = enrichment.get("epss_score", 0)
    has_patch = enrichment.get("has_patch", False)

    if severity == "critical" and epss > 0.5:
        return "PATCH IMMEDIATELY — critical severity with active exploitation detected"
    if severity == "critical":
        return "PATCH THIS SPRINT — critical severity"
    if severity == "high" and epss > 0.1:
        return "PATCH THIS SPRINT — high severity with likely exploitation"
    if severity == "high" and has_patch:
        return "PATCH NEXT SPRINT — high severity patch available"
    if severity == "high":
        return "TRACK AND MITIGATE — high severity, monitor for patch"
    if severity == "medium":
        return "SCHEDULE FOR NEXT QUARTER — medium severity"
    return "TRACK — low/informational severity"

def compare_scans(scan_a: dict, scan_b: dict) -> dict:
    """
    Diff two scans of the same target.

    Args:
        scan_a: Earlier scan (the baseline)
        scan_b: Later scan (the current state)

    Returns:
        A structured diff showing new, resolved, and persistent findings.

    Why template-id as the key?
    Template IDs are stable identifiers for vulnerability types.
    The same vulnerability can appear at different matched-at URLs,
    but the same template-id on the same host means the same root issue.
    """
    def finding_key(f: dict) -> str:
        """Stable key: template-id + host."""
        return f"{f.get('template-id', '')}::{f.get('host', '')}"

    findings_a = {finding_key(f): f for f in scan_a.get("results", [])}
    findings_b = {finding_key(f): f for f in scan_b.get("results", [])}

    keys_a = set(findings_a.keys())
    keys_b = set(findings_b.keys())

    new_findings       = [findings_b[k] for k in keys_b - keys_a]
    resolved_findings  = [findings_a[k] for k in keys_a - keys_b]
    persistent_findings = [findings_b[k] for k in keys_a & keys_b]

    # Security posture: are we getting better or worse?
    critical_new      = sum(1 for f in new_findings      if f.get("severity") == "critical")
    critical_resolved = sum(1 for f in resolved_findings if f.get("severity") == "critical")

    if len(new_findings) == 0 and len(resolved_findings) > 0:
        trend = "IMPROVING"
    elif critical_new > 0:
        trend = "DEGRADING"
    elif len(new_findings) > len(resolved_findings):
        trend = "DEGRADING"
    elif len(resolved_findings) > len(new_findings):
        trend = "IMPROVING"
    else:
        trend = "STABLE"

    return {
        "baseline_scan_id":   scan_a.get("scan_id"),
        "current_scan_id":    scan_b.get("scan_id"),
        "baseline_timestamp": scan_a.get("timestamp"),
        "current_timestamp":  scan_b.get("timestamp"),
        "target":             scan_b.get("target"),

        "summary": {
            "new_findings":       len(new_findings),
            "resolved_findings":  len(resolved_findings),
            "persistent_findings": len(persistent_findings),
            "security_trend":     trend,
            "critical_introduced": critical_new,
            "critical_resolved":  critical_resolved,
        },

        "new_findings":        new_findings,
        "resolved_findings":   resolved_findings,
        "persistent_findings": persistent_findings,
    }
