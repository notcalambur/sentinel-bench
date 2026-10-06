"""Normalize each source into a common advisory/vulnerability shape.

Output shape for advisories:
  {
    "external_id": str,
    "url": str | None,
    "title": str | None,
    "summary": str | None,
    "severity": "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"unknown",
    "published_at": iso8601 str | None,
    "cve_ids": list[str],
    "vendors": list[str],
    "products": list[str],
    "is_kev": bool,
    "exploitation_status": "confirmed"|"probable"|"poc"|"none"|"unknown",
    "raw": dict  # source-specific trimmed payload
  }

Output shape for vulnerability records (separate from advisories):
  {
    "cve_id": str,
    "cvss_v3_score": float | None,
    "cvss_v3_vector": str | None,
    "epss_score": float | None,
    "epss_percentile": float | None,
    "is_kev": bool,
    "kev_date_added": str | None,  # iso date
    "exploited_in_wild": bool,
    "poc_public": bool,
    "poc_urls": list[str],
    "description": str | None,
    "vendors": list[str],
    "products": list[str],
    "refs": [{"source": str, "url": str, "kind": str}],
  }
"""
from datetime import datetime, timezone
from typing import Any


def _iso(dt: Any) -> str | None:
    """Normalize a datetime-ish value to ISO 8601 string."""
    if dt is None:
        return None
    if isinstance(dt, str):
        return dt
    if isinstance(dt, (int, float)):
        # Treat as epoch seconds
        return datetime.fromtimestamp(dt, tz=timezone.utc).isoformat()
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    return str(dt)


def _severity_norm(s: Any) -> str:
    """Map any vendor severity to a 5-bucket standard."""
    if s is None:
        return "unknown"
    t = str(s).upper().strip()
    if t in ("CRITICAL",):
        return "CRITICAL"
    if t in ("HIGH", "IMPORTANT"):
        return "HIGH"
    if t in ("MEDIUM", "MODERATE"):
        return "MEDIUM"
    if t in ("LOW",):
        return "LOW"
    return "unknown"


# ---------- CISA KEV ----------
def normalize_kev(item: dict) -> dict:
    return {
        "external_id": item.get("cveID", ""),
        "url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog#{item.get('cveID','')}",
        "title": f"{item.get('cveID')} in {item.get('product','')}",
        "summary": item.get("shortDescription") or item.get("description", ""),
        "severity": "unknown",  # KEV doesn't carry CVSS
        "published_at": _iso(item.get("dateAdded")),
        "cve_ids": [item["cveID"]] if item.get("cveID") else [],
        "vendors": [item["vendor"]] if item.get("vendor") else [],
        "products": [item["product"]] if item.get("product") else [],
        "is_kev": True,
        "exploitation_status": "confirmed",
        "raw": {
            "cveID": item.get("cveID"),
            "vendor": item.get("vendor"),
            "product": item.get("product"),
            "vulnerabilityName": item.get("vulnerabilityName"),
            "dateAdded": item.get("dateAdded"),
            "dueDate": item.get("dueDate"),
            "requiredAction": item.get("requiredAction"),
            "shortDescription": item.get("shortDescription"),
        },
    }


# ---------- EPSS ----------
def normalize_epss(item: dict) -> dict | None:
    cve = item.get("cve")
    if not cve:
        return None
    return {
        "external_id": cve,
        "url": f"https://api.first.org/data/v1/epss?cve={cve}",
        "title": f"EPSS score for {cve}",
        "summary": f"EPSS={item.get('epss')} percentile={item.get('percentile')}",
        "severity": "unknown",
        "published_at": _iso(item.get("date")),
        "cve_ids": [cve],
        "vendors": [],
        "products": [],
        "is_kev": False,
        "exploitation_status": "unknown",
        "raw": item,
    }


def normalize_epss_to_vuln(item: dict) -> dict:
    cve = item.get("cve", "")
    epss = float(item["epss"]) if item.get("epss") is not None else None
    pct = float(item["percentile"]) if item.get("percentile") is not None else None
    return {
        "cve_id": cve,
        "epss_score": epss,
        "epss_percentile": pct,
        "is_kev": False,
        "kev_date_added": None,
        "exploited_in_wild": False,
        "poc_public": False,
        "poc_urls": [],
        "description": None,
        "vendors": [],
        "products": [],
        "refs": [],
    }


# ---------- GHSA ----------
def normalize_ghsa(item: dict) -> dict:
    cve_ids = []
    for c in item.get("identifiers", []) or []:
        if isinstance(c, dict) and c.get("type") == "CVE":
            cve_ids.append(c["value"])
    if not cve_ids and item.get("cve_id"):
        cve_ids = [item["cve_id"]]
    # Severity can be in top-level 'severity' or nested 'cvss_severities' / 'cvss'
    sev = item.get("severity") or (item.get("cvss_severities") or {}).get("rating") if isinstance(item.get("cvss_severities"), dict) else None
    severity = _severity_norm(sev)
    # References can be list[str] or list[dict]
    refs_raw = item.get("references") or []
    poc_urls = []
    for r in refs_raw:
        url = r if isinstance(r, str) else (r.get("url", "") if isinstance(r, dict) else "")
        if not url:
            continue
        if "exploit" in url.lower() or "poc" in url.lower() or "proof-of-concept" in url.lower():
            poc_urls.append(url)
    # Vendors from vulnerabilities[].package.ecosystem+name
    vendors = set()
    products = set()
    for v in item.get("vulnerabilities", []) or []:
        pkg = v.get("package") or {}
        if isinstance(pkg, dict):
            eco = pkg.get("ecosystem")
            name = pkg.get("name")
            if name:
                products.add(name)
                # ecosystem as vendor proxy
                if eco:
                    vendors.add(str(eco))
    return {
        "external_id": item.get("ghsa_id") or item.get("id", ""),
        "url": item.get("html_url") or item.get("url"),
        "title": (item.get("summary", "")[:200] if item.get("summary") else item.get("ghsa_id")),
        "summary": item.get("description", ""),
        "severity": severity,
        "published_at": _iso(item.get("published_at")),
        "cve_ids": cve_ids,
        "vendors": sorted(vendors),
        "products": sorted(products),
        "is_kev": False,
        "exploitation_status": "poc" if poc_urls else "unknown",
        "raw": {
            "ghsa_id": item.get("ghsa_id"),
            "cve_id": item.get("cve_id"),
            "summary": item.get("summary"),
            "severity": sev,
            "published_at": item.get("published_at"),
            "updated_at": item.get("updated_at"),
            "withdrawn_at": item.get("withdrawn_at"),
            "references_count": len(refs_raw),
        },
    }


def normalize_ghsa_to_vuln(item: dict) -> dict | None:
    """Extract vuln-level fields from GHSA. Used for the vulnerabilities table."""
    cve = ""
    for ident in item.get("identifiers", []) or []:
        if isinstance(ident, dict) and ident.get("type") == "CVE":
            cve = ident["value"]
            break
    if not cve:
        cve = item.get("cve_id", "")
    if not cve:
        return None  # GHSA without CVE → skip vuln table
    # cvss can be dict {vector_string, score} or list of such dicts
    cvss_obj = item.get("cvss")
    cvss_v3 = None
    cvss_v3_vector = None
    if isinstance(cvss_obj, dict):
        if cvss_obj.get("score") is not None:
            cvss_v3 = float(cvss_obj["score"])
            cvss_v3_vector = cvss_obj.get("vector_string")
    elif isinstance(cvss_obj, list):
        for vs in cvss_obj:
            if isinstance(vs, dict) and vs.get("version") in ("3.0", "3.1") and vs.get("score") is not None:
                cvss_v3 = float(vs["score"])
                cvss_v3_vector = vs.get("vector_string")
                break
    refs_raw = item.get("references") or []
    poc_urls = []
    for r in refs_raw:
        url = r if isinstance(r, str) else (r.get("url", "") if isinstance(r, dict) else "")
        if not url:
            continue
        if "exploit" in url.lower() or "poc" in url.lower() or "proof-of-concept" in url.lower():
            poc_urls.append(url)
    refs = []
    for r in refs_raw[:10]:
        url = r if isinstance(r, str) else (r.get("url", "") if isinstance(r, dict) else "")
        if url:
            refs.append({"source": "ghsa", "url": url, "kind": "advisory"})
    return {
        "cve_id": cve,
        "cvss_v3_score": cvss_v3,
        "cvss_v3_vector": cvss_v3_vector,
        "is_kev": False,
        "kev_date_added": None,
        "exploited_in_wild": False,
        "poc_public": bool(poc_urls),
        "poc_urls": poc_urls,
        "description": item.get("description", "")[:2000] if item.get("description") else None,
        "vendors": [],
        "products": [],
        "refs": refs,
    }


# ---------- NVD ----------
def normalize_nvd(item: dict) -> dict:
    """Extract advisory-shaped row from NVD CVE 2.0."""
    cve = item.get("id") or ""
    metrics = item.get("metrics", {}) or {}
    cvss_v3 = None
    cvss_v3_vector = None
    cvss_v4 = None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        for m in metrics.get(key, []) or []:
            cd = m.get("cvssData", {})
            if cvss_v3 is None and cd.get("baseScore") is not None:
                cvss_v3 = float(cd["baseScore"])
                cvss_v3_vector = cd.get("vectorString")
    for m in metrics.get("cvssMetricV4", []) or []:
        cd = m.get("cvssData", {})
        if cd.get("baseScore") is not None:
            cvss_v4 = float(cd["baseScore"])
    descriptions = item.get("descriptions", []) or []
    desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
    refs = item.get("references", []) or []
    vendors, products = set(), set()
    for cfg in item.get("configurations", []) or []:
        for node in cfg.get("nodes", []) or []:
            for cpe in node.get("cpeMatch", []) or []:
                if cpe.get("vulnerable"):
                    crit = cpe.get("criteria", "")
                    parts = crit.split(":")
                    if len(parts) >= 5:
                        vendors.add(parts[3])
                        products.add(parts[4])
    severity = "unknown"
    if cvss_v3 is not None:
        if cvss_v3 >= 9.0: severity = "CRITICAL"
        elif cvss_v3 >= 7.0: severity = "HIGH"
        elif cvss_v3 >= 4.0: severity = "MEDIUM"
        else: severity = "LOW"
    poc_urls = [r["url"] for r in refs if "exploit" in r.get("url", "").lower()]
    return {
        "external_id": cve,
        "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
        "title": cve,
        "summary": desc_en[:1000] if desc_en else None,
        "severity": severity,
        "published_at": _iso(item.get("published")),
        "cve_ids": [cve] if cve else [],
        "vendors": sorted(vendors),
        "products": sorted(products),
        "is_kev": False,
        "exploitation_status": "poc" if poc_urls else "unknown",
        "raw": {
            "id": cve,
            "published": item.get("published"),
            "lastModified": item.get("lastModified"),
            "metrics_keys": list(metrics.keys()),
            "refs_count": len(refs),
        },
    }


def normalize_nvd_to_vuln(item: dict) -> dict:
    cve = item.get("id") or ""
    metrics = item.get("metrics", {}) or {}
    cvss_v3 = None
    cvss_v3_vector = None
    cvss_v4 = None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        for m in metrics.get(key, []) or []:
            cd = m.get("cvssData", {})
            if cvss_v3 is None and cd.get("baseScore") is not None:
                cvss_v3 = float(cd["baseScore"])
                cvss_v3_vector = cd.get("vectorString")
    for m in metrics.get("cvssMetricV4", []) or []:
        cd = m.get("cvssData", {})
        if cd.get("baseScore") is not None:
            cvss_v4 = float(cd["baseScore"])
    descriptions = item.get("descriptions", []) or []
    desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
    refs = item.get("references", []) or []
    vendors, products = set(), set()
    for cfg in item.get("configurations", []) or []:
        for node in cfg.get("nodes", []) or []:
            for cpe in node.get("cpeMatch", []) or []:
                if cpe.get("vulnerable"):
                    crit = cpe.get("criteria", "")
                    parts = crit.split(":")
                    if len(parts) >= 5:
                        vendors.add(parts[3])
                        products.add(parts[4])
    poc_urls = [r["url"] for r in refs if "exploit" in r.get("url", "").lower()]
    # NVD doesn't have a dedicated remediation field. The closest signal
    # is vendor advisory URLs in `references` (MS/Cisco/Adobe/etc. security
    # bulletins). ponytail: vendor list is hard-coded; expand to a lookup
    # table if we onboard more vendors.
    _VENDOR_HOSTS = (
        # OS / hyperscalers
        "microsoft.com", "msrc.microsoft.com", "apple.com", "google.com",
        "chromium.org", "support.google.com", "support.apple.com",
        # Browsers / runtimes
        "mozilla.org", "oracle.com", "java.com", "openjdk.org",
        # Vendors with high-volume advisories
        "adobe.com", "cisco.com", "intel.com", "amd.com", "nvidia.com",
        "redhat.com", "vmware.com", "sap.com", "ibm.com",
        "juniper.net", "fortinet.com", "paloaltonetworks.com",
        "citrix.com", "dell.com", "hpe.com", "lenovo.com", "broadcom.com",
        "symantec.com", "f5.com", "checkpoint.com", "snyk.io",
        "siemens.com", "schneider-electric.com",
        # Linux distros
        "ubuntu.com", "debian.org", "suse.com", "archlinux.org",
        # Package managers / registries
        "npmjs.com", "pypi.org", "rubygems.org", "maven.apache.org",
    )
    vendor_refs = [
        r for r in refs
        if any(host in r.get("url", "").lower() for host in _VENDOR_HOSTS)
        and (
            r.get("type") in ("Vendor Advisory", "Patch", "Mitigation")
            or r.get("type") is None  # NVD often returns null for vendor advisories
        )
    ]
    remediation = None
    if vendor_refs:
        remediation = (
            f"See vendor advisory: {vendor_refs[0]['url']}"
            + (f" (+{len(vendor_refs) - 1} more)" if len(vendor_refs) > 1 else "")
        )[:1000]
    return {
        "cve_id": cve,
        "cvss_v3_score": cvss_v3,
        "cvss_v3_vector": cvss_v3_vector,
        "cvss_v4_score": cvss_v4,
        "is_kev": False,
        "kev_date_added": None,
        "exploited_in_wild": False,
        "poc_public": bool(poc_urls),
        "poc_urls": poc_urls,
        "description": desc_en[:2000] if desc_en else None,
        "remediation": remediation,
        "vendors": sorted(vendors),
        "products": sorted(products),
        "refs": [{"source": "nvd", "url": r["url"], "kind": r.get("type","reference")} for r in refs[:15]],
    }


# ---------- MSRC ----------
def normalize_msrc(item: dict) -> dict | None:
    """One MSRC 'update' doc → advisory. The list view (v2/updates) has no Severity
    or CVE numbers — those require fetching the per-doc CVRF (XML, ~3MB each).
    For MVP we record the security-update announcement as a single advisory so it
    appears in the dashboard 'sources' view, but we do NOT enrich with CVE-level
    fields. CVE-level enrichment for MSRC is a future iteration (parse CVRF XML)."""
    title = item.get("DocumentTitle") or ""
    alias = item.get("Alias") or item.get("ID") or ""
    # Filter: keep only actual "Security Updates" / "Cumulative" releases.
    # Skip Mariner release notes (Linux distro changelog).
    if not any(k in title for k in ("Security Updates", "Cumulative Update", "Servicing")):
        return None
    return {
        "external_id": alias,
        "url": item.get("CvrfUrl"),
        "title": title or alias,
        "summary": f"Microsoft {alias} — security release. CVE-level details require CVRF doc fetch (future).",
        "severity": "unknown",
        "published_at": _iso(item.get("InitialReleaseDate")),
        "cve_ids": [],  # empty by design (see docstring)
        "vendors": ["microsoft"],
        "products": [],
        "is_kev": False,
        "exploitation_status": "unknown",
        "raw": {
            "id": item.get("ID"),
            "alias": alias,
            "title": title,
            "initial_release_date": item.get("InitialReleaseDate"),
            "current_release_date": item.get("CurrentReleaseDate"),
            "cvrf_url": item.get("CvrfUrl"),
        },
    }