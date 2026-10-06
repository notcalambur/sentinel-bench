#!/usr/bin/env python3
"""Tests for ingest/lib/normalize.py — same console+exit style as cvss.test.ts.

Run: python3 ingest/lib/test_normalize.py
"""
import sys
from pathlib import Path

# allow `python3 ingest/lib/test_normalize.py` from project root
# IMPORTANT: insert PROJECT root first so `urllib.request` (which imports
# `http.client`) doesn't get shadowed by the project's `ingest/lib/http.py`.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ingest.lib.normalize import (
    normalize_kev,
    normalize_nvd, normalize_nvd_to_vuln,
    normalize_ghsa, normalize_ghsa_to_vuln,
    normalize_epss, normalize_epss_to_vuln,
    normalize_msrc,
)
from ingest.lib.score import score_breakdown, compute_score

passed, failed = 0, 0


def check(label, ok):
    global passed, failed
    if ok:
        print(f"  PASS  {label}")
        passed += 1
    else:
        print(f"  FAIL  {label}")
        failed += 1


def test_normalize_kev_minimal():
    """KEV entry with required fields → advisory has all required keys."""
    item = {
        "cveID": "CVE-2024-0001",
        "vendor": "Acme",
        "product": "Widget",
        "dateAdded": "2024-01-15",
        "dueDate": "2024-02-01",
        "shortDescription": "Buffer overflow in Widget.",
        "requiredAction": "Apply vendor patch.",
    }
    out = normalize_kev(item)
    check("kev external_id", out["external_id"] == "CVE-2024-0001")
    check("kev title has product", "Widget" in out["title"])
    check("kev vendors populated", out["vendors"] == ["Acme"])
    check("kev products populated", out["products"] == ["Widget"])
    check("kev cve_ids populated", "CVE-2024-0001" in out["cve_ids"])
    check("kev is_kev=True", out["is_kev"] is True)
    check("kev exploitation_status=confirmed", out["exploitation_status"] == "confirmed")
    check("kev raw carries requiredAction",
          out["raw"].get("requiredAction") == "Apply vendor patch.")


def test_normalize_nvd_to_vuln_remediation():
    """NVD vuln with vendor advisory → remediation populated."""
    item = {
        "id": "CVE-2024-1234",
        "metrics": {},
        "descriptions": [{"lang": "en", "value": "Test"}],
        "references": [
            {"url": "https://msrc.microsoft.com/update/CVE-2024-1234", "type": "Vendor Advisory"},
        ],
        "configurations": [],
    }
    out = normalize_nvd_to_vuln(item)
    check("nvd cve_id", out["cve_id"] == "CVE-2024-1234")
    check("nvd remediation from MS", out["remediation"] and "microsoft.com" in out["remediation"])
    check("nvd description truncated to 2000", len(out["description"]) <= 2000)
    check("nvd has poc_public=False", out["poc_public"] is False)


def test_normalize_nvd_to_vuln_no_remediation():
    """NVD vuln with no vendor advisory → remediation is None."""
    item = {
        "id": "CVE-2024-9999",
        "metrics": {},
        "descriptions": [],
        "references": [{"url": "https://example.com/news", "type": "Press/Media Coverage"}],
        "configurations": [],
    }
    out = normalize_nvd_to_vuln(item)
    check("nvd no vendor → remediation is None", out["remediation"] is None)


def test_normalize_nvd_to_vuln_multi_vendor():
    """NVD with multiple vendor advisories → remediation shows count."""
    item = {
        "id": "CVE-2024-0002",
        "metrics": {},
        "descriptions": [],
        "references": [
            {"url": "https://cisco.com/sec", "type": "Vendor Advisory"},
            {"url": "https://microsoft.com/sec", "type": "Vendor Advisory"},
        ],
        "configurations": [],
    }
    out = normalize_nvd_to_vuln(item)
    check("nvd multi → +1 more suffix", "+1 more" in out["remediation"])


def test_normalize_ghsa_minimal():
    """GHSA entry → advisory has the canonical keys."""
    item = {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "summary": "Test advisory",
        "description": "Detailed description",
        "severity": "high",
        "published_at": "2024-03-01T00:00:00Z",
        "references": [{"url": "https://example.com"}],
        "vulnerabilities": [{"package": {"name": "foo"}, "vulnerable_version_range": "<1.0"}],
    }
    out = normalize_ghsa(item)
    check("ghsa external_id", out["external_id"] == "GHSA-xxxx-yyyy-zzzz")
    check("ghsa severity mapped", out["severity"] in ("high", "medium", "low", "critical", "unknown"))


def test_normalize_msrc_filters_non_security():
    """MSRC: only Security Updates / Cumulative / Servicing get through."""
    sec = {"DocumentTitle": "March 2024 Security Updates", "Alias": "2024-Mar"}
    non_sec = {"DocumentTitle": "Service Retirement", "Alias": "2024-Mar"}
    serv = {"DocumentTitle": "Cumulative Servicing Stack Update", "Alias": "2024-Mar"}
    check("msrc security update kept", normalize_msrc(sec) is not None)
    check("msrc non-security dropped", normalize_msrc(non_sec) is None)
    check("msrc servicing update kept", normalize_msrc(serv) is not None)


def test_score_breakdown_basic():
    """compute_score with kev + high epss → high score."""
    vuln = {
        "is_kev": True,
        "exploited_in_wild": True,
        "epss_score": 0.99,
        "epss_percentile": 0.99,
        "cvss_v3_score": 9.8,
        "exploitation_status": "confirmed",
        "first_seen_at": "2024-01-01T00:00:00Z",
    }
    score, _breakdown = compute_score(vuln)
    check("score is float", isinstance(score, float))
    check("score > 50 for KEV+99%epss", score > 50)


def test_score_breakdown_zero_signals():
    """compute_score with no signals → low score."""
    vuln = {
        "is_kev": False,
        "exploited_in_wild": False,
        "epss_score": 0.0,
        "epss_percentile": 0.0,
        "cvss_v3_score": None,
        "exploitation_status": None,
        "first_seen_at": None,
    }
    score, _breakdown = compute_score(vuln)
    check("no signals → score < 20", score < 20)


print("=== test_normalize.py ===")
test_normalize_kev_minimal()
test_normalize_nvd_to_vuln_remediation()
test_normalize_nvd_to_vuln_no_remediation()
test_normalize_nvd_to_vuln_multi_vendor()
test_normalize_ghsa_minimal()
test_normalize_msrc_filters_non_security()
test_score_breakdown_basic()
test_score_breakdown_zero_signals()

print(f"\n{passed} passed, {failed} failed")
sys.exit(0 if failed == 0 else 1)
