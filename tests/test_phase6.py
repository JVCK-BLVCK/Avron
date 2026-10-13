# tests/test_phase6.py
"""
Tests for Phase 6 MCP tools — history, enrichment, reports, comparison.

These tests use the in-memory storage fixture from conftest.py
and mock external API calls (NVD, EPSS) so tests are:
  - Fast (no real network calls)
  - Deterministic (no external API variability)
  - Offline-capable (no internet required in CI)
"""
import json
from unittest.mock import AsyncMock, patch


# Sample scan data fixtures
COMPLETED_SCAN = {
    "scan_id":   "scan-001",
    "target":    "https://example.com",
    "status":    "completed",
    "timestamp": "2024-01-01T10:00:00Z",
    "error":     None,
    "results": [
        {
            "template-id": "CVE-2021-44228",
            "name":        "Log4Shell",
            "severity":    "critical",
            "host":        "https://example.com",
            "matched-at":  "https://example.com/api/log"
        },
        {
            "template-id": "xss-generic",
            "name":        "XSS",
            "severity":    "medium",
            "host":        "https://example.com",
            "matched-at":  "https://example.com/search"
        }
    ]
}

OLDER_SCAN = {
    "scan_id":   "scan-000",
    "target":    "https://example.com",
    "status":    "completed",
    "timestamp": "2024-01-01T09:00:00Z",
    "error":     None,
    "results": [
        {
            "template-id": "CVE-2021-44228",
            "name":        "Log4Shell",
            "severity":    "critical",
            "host":        "https://example.com",
            "matched-at":  "https://example.com/api/log"
        },
        {
            "template-id": "CVE-2020-1472",
            "name":        "Zerologon",
            "severity":    "critical",
            "host":        "https://example.com",
            "matched-at":  "https://example.com"
        }
    ]
}

MOCK_NVD_RESPONSE = {
    "cvss_score":    9.8,
    "cvss_severity": "CRITICAL",
    "cvss_vector":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "description":   "Apache Log4j2 JNDI injection vulnerability",
    "cwe_ids":       ["CWE-917"],
    "has_patch":     True,
    "nvd_url":       "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
}

MOCK_EPSS_RESPONSE = {
    "epss_score":      0.97,
    "epss_percentile": 0.99,
    "epss_date":       "2024-01-01"
}


# ─── get_scan_history ─────────────────────────────────────────────────────────

async def test_get_scan_history_returns_scans(use_in_memory_storage):
    """History tool must return scans for a known target."""
    from app.mcp_server import get_scan_history

    use_in_memory_storage["scan-001"] = COMPLETED_SCAN
    use_in_memory_storage["scan-000"] = OLDER_SCAN

    with patch("app.mcp_server.get_scans_by_target",
               new=AsyncMock(return_value=[COMPLETED_SCAN, OLDER_SCAN])):
        result   = await get_scan_history(target_url="https://example.com")
        response = json.loads(result)

    assert response["total_scans"]        == 2
    assert response["target"]             == "https://example.com"
    assert len(response["scans"])         == 2
    assert "trend"                        in response


async def test_get_scan_history_unknown_target_returns_empty(use_in_memory_storage):
    """Unknown target must return empty list, not error."""
    from app.mcp_server import get_scan_history

    with patch("app.mcp_server.get_scans_by_target",
               new=AsyncMock(return_value=[])):
        result   = await get_scan_history(target_url="https://unknown.com")
        response = json.loads(result)

    assert response["scans"]  == []
    assert "message"          in response


async def test_get_scan_history_empty_url_returns_error():
    """Empty URL must return error."""
    from app.mcp_server import get_scan_history
    result   = await get_scan_history(target_url="")
    response = json.loads(result)
    assert "error" in response


# ─── analyse_findings ─────────────────────────────────────────────────────────

async def test_analyse_findings_enriches_cve(use_in_memory_storage):
    """CVE findings must be enriched with CVSS and EPSS data."""
    from app.mcp_server import analyse_findings

    use_in_memory_storage["scan-001"] = COMPLETED_SCAN

    with patch("app.enrichment.get_nvd_data",
               new=AsyncMock(return_value=MOCK_NVD_RESPONSE)), \
         patch("app.enrichment.get_epss_score",
               new=AsyncMock(return_value=MOCK_EPSS_RESPONSE)):
        result   = await analyse_findings(scan_id="scan-001")
        response = json.loads(result)

    assert response["total_findings"]       == 2
    assert "enriched_findings"              in response
    assert len(response["enriched_findings"]) == 2


async def test_analyse_findings_incomplete_scan_returns_error(use_in_memory_storage):
    """Analysis must fail clearly on incomplete scans."""
    from app.mcp_server import analyse_findings

    use_in_memory_storage["scan-in-progress"] = {
        **COMPLETED_SCAN,
        "scan_id": "scan-in-progress",
        "status":  "in_progress"
    }
    result   = await analyse_findings(scan_id="scan-in-progress")
    response = json.loads(result)
    assert "error" in response


async def test_analyse_findings_empty_scan_returns_no_findings(use_in_memory_storage):
    """Empty scan results return no findings gracefully."""
    from app.mcp_server import analyse_findings

    use_in_memory_storage["scan-empty"] = {
        **COMPLETED_SCAN,
        "scan_id": "scan-empty",
        "results": []
    }
    result   = await analyse_findings(scan_id="scan-empty")
    response = json.loads(result)
    assert response.get("findings", []) == [] or response.get("message") is not None


# ─── generate_report ─────────────────────────────────────────────────────────

async def test_generate_report_structure(use_in_memory_storage):
    """Report must contain all required structural fields."""
    from app.mcp_server import generate_report

    use_in_memory_storage["scan-001"] = COMPLETED_SCAN

    with patch("app.enrichment.enrich_findings",
               new=AsyncMock(return_value=COMPLETED_SCAN["results"])):
        result   = await generate_report(
            scan_id="scan-001",
            include_enrichment=False
        )
        response = json.loads(result)

    assert "executive_summary"      in response
    assert "findings_by_severity"   in response
    assert "remediation_priorities" in response
    assert "report_id"              in response


async def test_generate_report_risk_rating(use_in_memory_storage):
    """Report with critical findings must have CRITICAL risk rating."""
    from app.mcp_server import generate_report

    use_in_memory_storage["scan-001"] = COMPLETED_SCAN

    result   = await generate_report(scan_id="scan-001", include_enrichment=False)
    response = json.loads(result)

    assert response["executive_summary"]["risk_rating"] == "CRITICAL"
    assert response["executive_summary"]["breakdown"]["critical"] == 1


async def test_generate_report_clean_scan(use_in_memory_storage):
    """Clean scan must report CLEAN risk rating."""
    from app.mcp_server import generate_report

    use_in_memory_storage["scan-clean"] = {
        **COMPLETED_SCAN,
        "scan_id": "scan-clean",
        "results": []
    }
    result   = await generate_report(scan_id="scan-clean", include_enrichment=False)
    response = json.loads(result)
    assert response["executive_summary"]["risk_rating"] == "CLEAN"


# ─── compare_scans ────────────────────────────────────────────────────────────

async def test_compare_scans_identifies_new_findings(use_in_memory_storage):
    """New findings in current scan must appear in new_findings."""
    from app.mcp_server import compare_scans

    use_in_memory_storage["scan-000"] = OLDER_SCAN
    use_in_memory_storage["scan-001"] = COMPLETED_SCAN

    result    = await compare_scans(
        baseline_scan_id="scan-000",
        current_scan_id="scan-001"
    )
    response  = json.loads(result)

    # XSS is in scan-001 but not scan-000 → should be new
    new_ids = [f.get("template-id") for f in response["new_findings"]]
    assert "xss-generic" in new_ids


async def test_compare_scans_identifies_resolved_findings(use_in_memory_storage):
    """Findings in baseline but not current must appear in resolved_findings."""
    from app.mcp_server import compare_scans

    use_in_memory_storage["scan-000"] = OLDER_SCAN
    use_in_memory_storage["scan-001"] = COMPLETED_SCAN

    result   = await compare_scans(
        baseline_scan_id="scan-000",
        current_scan_id="scan-001"
    )
    response = json.loads(result)

    # Zerologon (CVE-2020-1472) is in scan-000 but not scan-001 → resolved
    resolved_ids = [f.get("template-id") for f in response["resolved_findings"]]
    assert "CVE-2020-1472" in resolved_ids


async def test_compare_scans_security_trend(use_in_memory_storage):
    """Comparison must report security trend."""
    from app.mcp_server import compare_scans

    use_in_memory_storage["scan-000"] = OLDER_SCAN
    use_in_memory_storage["scan-001"] = COMPLETED_SCAN

    result   = await compare_scans(
        baseline_scan_id="scan-000",
        current_scan_id="scan-001"
    )
    response = json.loads(result)

    assert "security_trend" in response["summary"]
    # OLDER_SCAN has 2 findings, COMPLETED_SCAN has 2 findings
    # but different ones — depends on net change
    assert response["summary"]["security_trend"] in [
        "IMPROVING", "DEGRADING", "STABLE"
    ]


async def test_compare_scans_different_targets_returns_error(use_in_memory_storage):
    """Comparing scans of different targets must return error."""
    from app.mcp_server import compare_scans

    use_in_memory_storage["scan-a"] = {
        **COMPLETED_SCAN, "scan_id": "scan-a", "target": "https://site-a.com"
    }
    use_in_memory_storage["scan-b"] = {
        **COMPLETED_SCAN, "scan_id": "scan-b", "target": "https://site-b.com"
    }

    result   = await compare_scans(
        baseline_scan_id="scan-a",
        current_scan_id="scan-b"
    )
    response = json.loads(result)
    assert "error" in response


async def test_compare_scans_missing_baseline_returns_error(use_in_memory_storage):
    """Missing baseline scan must return clear error."""
    from app.mcp_server import compare_scans

    use_in_memory_storage["scan-001"] = COMPLETED_SCAN

    result   = await compare_scans(
        baseline_scan_id="nonexistent",
        current_scan_id="scan-001"
    )
    response = json.loads(result)
    assert "error" in response


# ─── Unit tests for report and enrichment modules ────────────────────────────

def test_generate_report_severity_grouping():
    """Findings must be correctly grouped by severity."""
    from app.report import generate_report

    report = generate_report(COMPLETED_SCAN)
    assert "critical" in report["findings_by_severity"]
    assert "medium"   in report["findings_by_severity"]
    assert len(report["findings_by_severity"]["critical"]) == 1


def test_compare_scans_persistent_findings():
    """CVE-2021-44228 appears in both scans — must be persistent."""
    from app.report import compare_scans

    diff = compare_scans(OLDER_SCAN, COMPLETED_SCAN)
    persistent_ids = [
        f.get("template-id") for f in diff["persistent_findings"]
    ]
    assert "CVE-2021-44228" in persistent_ids


async def test_enrich_finding_non_cve_skipped():
    """Non-CVE findings must be skipped without NVD/EPSS calls."""
    from app.enrichment import enrich_finding

    xss_finding = {
        "template-id": "xss-generic",
        "severity":    "medium",
        "host":        "https://example.com"
    }
    enriched = await enrich_finding(xss_finding)
    assert enriched["enrichment"]["source"] == "none"


async def test_enrich_finding_cve_fetches_data():
    """CVE findings must be enriched with CVSS and EPSS data."""
    from app.enrichment import enrich_finding

    cve_finding = {
        "template-id": "CVE-2021-44228",
        "severity":    "critical",
        "host":        "https://example.com"
    }

    with patch("app.enrichment.get_nvd_data",
               new=AsyncMock(return_value=MOCK_NVD_RESPONSE)), \
         patch("app.enrichment.get_epss_score",
               new=AsyncMock(return_value=MOCK_EPSS_RESPONSE)):
        enriched   = await enrich_finding(cve_finding)
        enrichment = enriched.get("enrichment", {})

    assert enrichment["cvss_score"] == 9.8
    assert enrichment["epss_score"] == 0.97
    assert enrichment["risk_label"] == "CRITICAL_ACTIVE"
