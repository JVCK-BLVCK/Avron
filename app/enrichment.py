"""
Vulnerability finding enrichment from external databases.

Two data sources:
  NVD (National Vulnerability Database) — CVSS severity scores, descriptions,
    CWE classifications, and patch availability. The authoritative source for
    CVE metadata. Rate limited to 5 requests/30s without an API key.

  EPSS (Exploit Prediction Scoring System) — probability that a CVE will be
    exploited in the wild within the next 30 days. Published daily by FIRST.org.
    Ranges 0.0-1.0. An EPSS score of 0.95 means 95% probability of exploitation.

Why two sources?
  CVSS measures theoretical severity (impact if exploited).
  EPSS measures practical risk (likelihood of exploitation).
  A CVE can be CVSS 9.8 (critical) but EPSS 0.002 (rarely exploited in practice).
  Combining both gives a far more accurate risk picture than either alone.

The FIRST.org research shows that 4% of vulnerabilities account for 77% of
actual exploitations. EPSS identifies which 4%. Without it, security teams
waste time on theoretical high-severity issues while real threats go unpatched.
"""

from app.config import settings

import asyncio
import logging
import httpx


logger = logging.getLogger(__name__)


NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cve/2.0"
EPSS_API_BASE = "https://api.first.org/data/v1/epss"
NVD_API_KEY = settings.nvd_api_key  # Optional, but increases
# rate limit from 5 requests/30s to 50 requests/30s. See https://nvd.nist.gov/developers/request-an-api-key


async def get_nvd_data(cve_id: str) -> dict:
    """
    Fetch CVE metadata from the NVD API.

    Args:
        cve_id (str): The CVE identifier (e.g., "CVE-2023-12345").

    Returns:
        dict: A dictionary containing CVE metadata, or None if not found.
    """
    if not cve_id.upper().startswith("CVE-"):
        return {}   # not a CVE ID — skip enrichment silently

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                NVD_API_BASE,
                params={"cveId": cve_id.upper()},
                headers=headers
            )
            if response.status_code != 200:
                return {}

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                return {}

            cve = vulnerabilities[0].get("cve", {})


            # Extract CVSS v3.1 score and then v2 (fallback)
            cvss_score = None
            cvss_severity = None
            cvss_vector = None

            metrics = cve.get("metrics", {})
            if "cvssMetricV31" in metrics:
                m             = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_score    = m.get("baseScore")
                cvss_severity = m.get("baseSeverity")
                cvss_vector   = m.get("vectorString")
            elif "cvssMetricV2" in metrics:
                m             = metrics["cvssMetricV2"][0]["cvssData"]
                cvss_score    = m.get("baseScore")
                cvss_severity = "MEDIUM" if cvss_score and cvss_score >= 4.0 else "LOW"


            # Extract description
            description = ""
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Extract CWE IDs
            cwe_ids = []
            for weakness in cve.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    if desc.get("value", "").startswith("CWE-"):
                        cwe_ids.append(desc.get("value"))

            # Check patch availability via references (look for "Patch" or "Vendor Advisory" in tags)
            has_patch = any(
                "Patch" in ref.get("tags", []) or "Vendor Advisory" in ref.get("tags", [])
                for ref in cve.get("references", [])
            )

            return {
                "cvss_score": cvss_score,
                "cvss_severity": cvss_severity,
                "cvss_vector": cvss_vector,
                "description": description,
                "cwe_ids": cwe_ids,
                "has_patch": has_patch,
                "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id.upper()}"
            }

    except Exception as e:
        logger.warning({
            "event": "nvd_enrichment_error",
            "cve_id": cve_id,
            "error": str(e)
        })

        return {}


async def get_epss_score(cve_id: str) -> dict:
    """
    Fetch the EPSS score for a given CVE ID.

    Args:
        cve_id (str): The CVE identifier (e.g., "CVE-2023-12345").

    Returns:
        dict: A dictionary containing the EPSS score and probability, or an empty dict if not found.

    EPSS score: 0.0-1.0 probability of exploitation within 30 days.
    EPSS percentile: rank among all CVEs (0.99 = top 1% most likely to be exploited).

    A CVE with EPSS 0.95 and CVSS 7.5 is more dangerous than one with
    EPSS 0.01 and CVSS 9.8 — the first is likely being exploited today,
    the second is severe but nobody is actively targeting it.

    """
    if not cve_id.upper().startswith("CVE-"):
        return {}   # not a CVE ID — skip enrichment silently

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                EPSS_API_BASE,
                params={"cve": cve_id.upper()}
            )
            if response.status_code != 200:
                return {}

            data = response.json()
            if "data" not in data or not data["data"]:
                return {}

            entry = data["data"][0]
            return {
                "epss_score": float(entry.get("epss", 0.0)),
                "epss_percentile": float(entry.get("percentile", 0.0)),
                "epss_date": entry.get("date", "")
            }
    except Exception as e:
        logger.warning({
            "event": "epss_enrichment_error",
            "cve_id": cve_id,
            "error": str(e)
        })
        return {}


async def enrich_finding(finding: dict) -> dict:
    """
    Enrich a vulnerability finding with NVD and EPSS data.

    Args:
        finding (dict): A dictionary containing the finding data, including 'cve_id'.

    Returns:
        dict: The enriched finding with additional metadata.

    Fetches NVD and EPSS concurrently — both are I/O bound, no reason
    to wait for one before starting the other.

    Returns the finding with enrichment fields added. Original fields
    are never modified — enrichment is additive only.

    """
    template_id = finding.get("template-id", "")

    # Skip enrichment for non-CVE templates (e.g., SAST, secret scanning, etc.)
    if not template_id.upper().startswith("CVE-"):
        return {
            **finding,
            "enrichment": {
                "source": "none",
                "reason": "Not a CVE template, no NVD/EPSS data available"
            }
        }


    # fetch NVD and EPSS concurrently — both are I/O bound, no reason
    # to wait for one before starting the other.
    nvd_data, epss_data = await asyncio.gather(
        get_nvd_data(template_id),
        get_epss_score(template_id),
        return_exceptions=True,
    )

    # gather with return_exceptions=True means exceptions become values.
    # Normalize each result to clsa plain mapping before dictionary unpacking,
    # otherwise type checkers see Exception|dict and complain that
    # the unpack operator requires a mapping.
    if not isinstance(nvd_data, dict):
        logger.warning({"event": "nvd_data_failed", "error": str(nvd_data)})
        nvd_data = {}
    if not isinstance(epss_data, dict):
        logger.warning({"event": "epss_data_failed", "error": str(epss_data)})
        epss_data = {}

    # Final unpacking remains type-safe because both branches are now plain dicts.
    enrichment = {
        "source": "nvd+epss",
        **nvd_data,
        **epss_data
    }

    # Compute a composite risk priority for the agent.
    # This combines severity + exploitability into a single score for prioritization.
    # Only when both data sources return usable values.
    if nvd_data.get("cvss_score") is not None and epss_data.get("epss_score") is not None:
        cvss = nvd_data["cvss_score"]
        epss = epss_data["epss_score"]
        # Priority = CVSS * EPSS * 10, weighted toward actively exploited
        enrichment["risk_priority"] = round(cvss * epss * 10, 2)
        enrichment["risk_label"] = (
            "CRITICAL_ACTIVE" if epss > 0.5 and cvss >= 9.0
            else "HIGH_ACTIVE" if epss > 0.1 and cvss >= 7.0
            else "HIGH_THEORETICAL" if cvss >= 7.0
            else "MEDIUM_ACTIVE" if epss > 0.1 and cvss >= 4.0
            else "MEDIUM_THEORETICAL" if cvss >= 4.0
            else "STANDARD"
        )

    return {**finding, "enrichment": enrichment}


async def enrich_findings(findings: list[dict]) -> list[dict]:
    """
    Enrich a list of vulnerability findings concurrently.

    Args:
        findings (list[dict]): A list of finding dictionaries, each containing 'template_id'.

    Returns:
        list[dict]: A list of enriched findings with additional metadata.

    This function uses asyncio.gather to run enrich_finding concurrently
    for all findings, improving performance for large batches.
    """
    if not findings:
        return []

    # Process in batches of 5 to respect NVD rate limiting (5 requests/30s without an API key).
    batch_size = 5
    enriched = []

    for i in range(0, len(findings), batch_size):
        batch = findings[i:i + batch_size]
        results = await asyncio.gather(
            *[enrich_finding(f) for f in batch],
            return_exceptions=True
        )
        for result, original in zip(results, batch):
            if isinstance(result, Exception):
                enriched.append({
                    **original,
                    "enrichment": {
                        "source": "error",
                        "reason": str(result)
                    }
                })
            else:
                enriched.append(result)

            # Brief pause between batches to avoid NVD rate limiting issues. Adjust as needed based on API key usage.
        if i + batch_size < len(findings):
            await asyncio.sleep(0.5)  # 500ms pause between batches

    return enriched
