#!/usr/bin/env python3
"""sentinel-bench ingest — fetch + normalize + upsert to Supabase.

CLI:
  python -m ingest.ingest --source=KEV          # one source
  python -m ingest.ingest --source=KEV,EPSS,GHSA  # multiple
  python -m ingest.ingest --source=all          # everything
  python -m ingest.ingest --source=KEV --limit=10  # cap items (for QA)

Idempotency: every advisory has content_hash; upsert merges by (source_id, external_id).
Vulnerabilities: upsert by cve_id, only if content changed.

Records a delivery_runs row at the end with counts + http_statuses.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path
import urllib.request

# Allow `python ingest/ingest.py` from project root
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ingest.lib import (
    SOURCES, http_get, http_get_json, get_env,
    normalize_kev, normalize_epss, normalize_epss_to_vuln, normalize_ghsa, normalize_ghsa_to_vuln,
    normalize_nvd, normalize_nvd_to_vuln, normalize_msrc,
    sha256_json, sb_get_source_id_cached, sb_upsert_advisory, sb_upsert_vuln,
    sb_record_run, sb_patch_run, sb_headers, sb_url, HTTPError,
)
from ingest.lib.ot import normalize_rss_ot, normalize_csaf_ot, normalize_moxa_html

def resolve_project_ref() -> str:
    ref = get_env("SUPABASE_PROJECT_REF")
    if ref:
        return ref
    url = get_env("PUBLIC_SUPABASE_URL") or get_env("SUPABASE_URL")
    if url:
        return url.replace("https://", "").replace(".supabase.co", "").split("/")[0]
    for p in ["/root/projects/sentinel-bench/.supabase-creds", str(Path.home() / ".supabase-creds"), ".supabase-creds"]:
        try:
            pth = Path(p)
            if pth.exists():
                text = pth.read_text()
                for line in text.splitlines():
                    if "=" in line:
                        return line.split("=", 1)[1].strip()
        except Exception:
            pass
    return "zctyivjngflpynzskxvy"

PROJECT_REF = resolve_project_ref()

# ----------------------------- per-source fetchers -----------------------------

def fetch_kev() -> tuple[list[dict], list[dict], dict]:
    """Returns (advisories_list, vuln_updates_list, http_status).

    KEV is the canonical source for is_kev=true and kev_date_added. We also write
    each row into the vulnerabilities table so the score formula can pick it up.
    """
    url = SOURCES["cisa_kev"]["url"]
    status, data = http_get_json(url)
    items = data.get("vulnerabilities", []) or []
    advisories, vulns = [], []
    for it in items:
        n = normalize_kev(it)
        n["content_hash"] = sha256_json(n["raw"])
        advisories.append(n)
        cve = (it.get("cveID") or "").strip()
        if not cve:
            continue
        # KEV carries dateAdded (string YYYY-MM-DD) and dueDate. Convert to ISO date.
        date_added = it.get("dateAdded")
        if date_added and "T" not in date_added:
            date_added = date_added[:10]  # YYYY-MM-DD
        vulns.append({
            "cve_id": cve,
            "is_kev": True,
            "kev_date_added": date_added,
            "exploited_in_wild": True,
            "remediation": (it.get("requiredAction") or "")[:1000] or None,
            "vendors": [it["vendor"]] if it.get("vendor") else [],
            "products": [it["product"]] if it.get("product") else [],
            "refs": [{"source": "cisa_kev", "url": n["url"], "kind": "kev"}] if n.get("url") else [],
        })
    return advisories, vulns, {"cisa_kev": status}


def fetch_epss(limit: int | None = None) -> tuple[list[dict], list[dict], dict]:
    """Fetch EPSS for known CVEs (only those already in advisories)."""
    # Get list of CVEs from advisories table to keep this cheap
    headers = sb_headers()
    req = urllib.request.Request(
        sb_url(PROJECT_REF, "/advisories?select=cve_ids&limit=500"),
        headers=headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            adv_rows = json.loads(resp.read())
    except Exception as e:
        return [], [], {"epss": 0}
    cves = sorted({c for r in adv_rows for c in (r.get("cve_ids") or []) if c.startswith("CVE-")})
    if not cves:
        return [], [], {"epss": 200}
    if limit:
        cves = cves[:limit]
    # Batch EPSS requests (100 per call is the safe limit)
    advisories, vulns = [], []
    for i in range(0, len(cves), 100):
        chunk = cves[i:i+100]
        url = f"https://api.first.org/data/v1/epss?cve={','.join(chunk)}"
        try:
            status, data = http_get_json(url)
        except HTTPError as e:
            print(f"EPSS chunk {i}: {e}", file=sys.stderr)
            continue
        for item in (data.get("data") or []):
            n = normalize_epss(item)
            if n:
                n["content_hash"] = sha256_json(n["raw"])
                advisories.append(n)
            v = normalize_epss_to_vuln(item)
            if v.get("cve_id"):
                vulns.append(v)
        time.sleep(0.5)
    return advisories, vulns, {"epss": 200}


def fetch_ghsa(limit: int = 50) -> tuple[list[dict], list[dict], dict]:
    """Fetch latest GitHub Security Advisories."""
    url = f"https://api.github.com/advisories?per_page={min(limit,100)}&sort=published&direction=desc"
    try:
        status, data = http_get_json(url)
    except HTTPError as e:
        return [], [], {"ghsa": e.status}
    advisories, vulns = [], []
    for item in (data or []):
        n = normalize_ghsa(item)
        n["content_hash"] = sha256_json(n["raw"])
        advisories.append(n)
        v = normalize_ghsa_to_vuln(item)
        if v:
            vulns.append(v)
    return advisories, vulns, {"ghsa": status}


def fetch_nvd(cve_ids: list[str] | None = None, limit: int = 20,
              last_mod_start: str | None = None, last_mod_end: str | None = None) -> tuple[list[dict], list[dict], dict]:
    """Fetch NVD for specific CVEs, or NVD-modified-since window.

    last_mod_start/end are ISO-8601 strings (e.g. '2026-07-28T00:00:00.000').
    When provided, NVD returns all CVEs modified in that window — use for daily diff.
    """
    nvd_key = get_env("NVD_API_KEY")
    headers = {"apiKey": nvd_key} if nvd_key else {}
    if cve_ids:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={','.join(cve_ids[:limit])}"
    elif last_mod_start and last_mod_end:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate={last_mod_start}&lastModEndDate={last_mod_end}&resultsPerPage={limit}"
    else:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage={limit}"
    try:
        status, data = http_get_json(url, headers=headers)
    except HTTPError as e:
        return [], [], {"nvd": e.status}
    advisories, vulns = [], []
    for item in (data.get("vulnerabilities") or []):
        cve = (item.get("cve") or {}).get("id") or item.get("id")
        if not cve: continue
        n = normalize_nvd(item["cve"] if "cve" in item else item)
        n["content_hash"] = sha256_json(n["raw"])
        advisories.append(n)
        v = normalize_nvd_to_vuln(item["cve"] if "cve" in item else item)
        if v.get("cve_id"):
            vulns.append(v)
        time.sleep(0.05)  # polite rate (NVD with key: 50/30s)
    return advisories, vulns, {"nvd": status}


def fetch_msrc(limit: int = 10) -> tuple[list[dict], list[dict], dict]:
    """Fetch MSRC updates list (skip non-security) + parse recent CVRF docs for CVE-level enrichment."""
    from ingest.lib.msrc_cvrf import parse_cvrf
    url = "https://api.msrc.microsoft.com/cvrf/v2.0/updates"
    try:
        status, data = http_get_json(url)
    except HTTPError as e:
        return [], [], {"msrc": e.status}
    items_all = data.get("value") or []
    # List is sorted oldest→newest; we want most recent first for both CVEs and CVRF fetch cost.
    items_all.sort(key=lambda x: x.get("InitialReleaseDate") or "", reverse=True)
    items = items_all[:limit]
    advisories, vulns = [], []
    for it in items:
        n = normalize_msrc(it)
        if n:
            n["content_hash"] = sha256_json(n["raw"])
            advisories.append(n)
        # Also fetch the per-doc CVRF for CVE-level fields (limit to recent 5 to keep cheap)
        cvrf_url = it.get("CvrfUrl")
        if cvrf_url:
            try:
                # cvrf v3 doc is XML. http_get returns bytes; feed to ET.
                s_code, body = http_get(cvrf_url, headers={"Accept": "application/xml,*/*"})
                if s_code == 200:
                    for rec in parse_cvrf(body):
                        vulns.append(rec)
            except Exception:
                continue  # one bad doc shouldn't kill the run
    return advisories, vulns, {"msrc": status}


# ----------------------------- OT fetchers -----------------------------
def fetch_ot_rss(slug: str, limit: int | None = None) -> tuple[list[dict], list[dict], dict]:
    """Shared no-dependency RSS path for public OT vendor feeds."""
    source = SOURCES[slug]
    try:
        status, body = http_get(source["url"], headers={"Accept": "application/rss+xml, application/xml, text/xml"})
        advisories = normalize_rss_ot(body.decode("utf-8", "replace"), vendor=source["vendor"], source=slug)
    except HTTPError as e:
        return [], [], {slug: e.status}
    if limit:
        advisories = advisories[:limit]
    for advisory in advisories:
        advisory["content_hash"] = sha256_json(advisory["raw"])
    return advisories, [], {slug: status}


def fetch_abb_psirt(limit: int | None = None) -> tuple[list[dict], list[dict], dict]:
    """Compatibility alias for ABB's public PSIRT RSS feed."""
    return fetch_ot_rss("abb_psirt", limit)


def fetch_ot_csaf(slug: str, limit: int | None = None) -> tuple[list[dict], list[dict], dict]:
    """Shared CSAF ROLIE feed path for vendors publishing structured OT advisories."""
    source = SOURCES[slug]
    try:
        status, index = http_get_json(source["url"])
    except HTTPError as e:
        return [], [], {slug: e.status}
    entries = ((index.get("feed") or {}).get("entry") or [])
    if limit:
        entries = entries[:limit]
    advisories: list[dict] = []
    for entry in entries:
        url = (entry.get("content") or {}).get("src") or next((x.get("href") for x in entry.get("link") or [] if x.get("rel") == "self"), None)
        if not url:
            continue
        try:
            _, doc = http_get_json(url)
        except HTTPError:
            continue
        advisories.extend(normalize_csaf_ot(doc, source["vendor"]))
    for advisory in advisories:
        advisory["content_hash"] = sha256_json(advisory["raw"])
    return advisories, [], {slug: status}


def fetch_abb_csaf(limit: int | None = None) -> tuple[list[dict], list[dict], dict]:
    """Compatibility alias for ABB's CSAF feed."""
    return fetch_ot_csaf("abb_csaf", limit)


def fetch_cisco_psirt(limit: int = 200) -> tuple[list[dict], list[dict], dict]:
    """Fetch Cisco's undocumented but public publication API (no key or auth)."""
    url = SOURCES["cisco_psirt"]["url"].replace("limit=200", f"limit={min(limit, 100)}")  # Cisco returns empty 200 above 100
    try:
        status, rows = http_get_json(url)
    except HTTPError as e:
        return [], [], {"cisco_psirt": e.status}
    advisories = []
    for row in rows or []:
        external_id = row.get("identifier")
        if not external_id:
            continue
        raw = {k: row.get(k) for k in ("identifier", "title", "severity", "summary", "firstPublished", "lastPublished", "url")}
        advisories.append({
            "external_id": external_id,
            "url": row.get("url"),
            "title": row.get("title") or external_id,
            "summary": row.get("summary") or "",
            "severity": str(row.get("severity") or "unknown").upper(),
            "published_at": row.get("firstPublished") or row.get("lastPublished"),
            "cve_ids": [],
            "vendors": ["cisco"],
            "products": [],
            "is_kev": False,
            "exploitation_status": "unknown",
            "domain": "OT",
            "raw": raw,
            "content_hash": sha256_json(raw),
        })
    return advisories, [], {"cisco_psirt": status}


def fetch_cisa_ics(limit: int = 100) -> tuple[list[dict], list[dict], dict]:
    """Fetch recent CISA OT CSAF docs from CISA's official GitHub mirror."""
    try:
        status, tree = http_get_json(SOURCES["cisa_ics"]["url"])
    except HTTPError as e:
        return [], [], {"cisa_ics": e.status}
    paths = sorted(
        x["path"] for x in tree.get("tree", [])
        if x.get("path", "").startswith("csaf_files/OT/white/") and x["path"].endswith(".json")
        and not x["path"].endswith("feed-tlp-white.json")
    )
    # ponytail: use recent lexical CSAF paths; switch to commit-time pagination if backlog precision matters.
    advisories: list[dict] = []
    for path in paths[-min(limit, 100):]:
        url = f"https://raw.githubusercontent.com/cisagov/CSAF/develop/{path}"
        try:
            _, doc = http_get_json(url)
        except HTTPError:
            continue
        advisories.extend(normalize_csaf_ot(doc, "cisa"))
    for advisory in advisories:
        advisory["content_hash"] = sha256_json(advisory["raw"])
    return advisories, [], {"cisa_ics": status}


def fetch_moxa(limit: int = 20) -> tuple[list[dict], list[dict], dict]:
    """Fetch Moxa's public server-rendered advisory table."""
    try:
        status, body = http_get(SOURCES["moxa"]["url"])
    except HTTPError as e:
        return [], [], {"moxa": e.status}
    advisories = normalize_moxa_html(body.decode("utf-8", "replace"))[:limit]
    for advisory in advisories:
        advisory["content_hash"] = sha256_json(advisory["raw"])
    return advisories, [], {"moxa": status}


def fetch_paloalto(limit: int = 100) -> tuple[list[dict], list[dict], dict]:
    """Fetch Palo Alto's public advisory JSON endpoint."""
    try:
        status, rows = http_get_json(SOURCES["paloalto"]["url"])
    except HTTPError as e:
        return [], [], {"paloalto": e.status}
    advisories = []
    for row in (rows or [])[:limit]:
        external_id = row.get("ID")
        if not external_id:
            continue
        cves = [external_id] if external_id.startswith("CVE-") else []
        summary = "; ".join(filter(None, [row.get("title"), f"Affected: {', '.join(row.get('affected') or [])}", f"Fixed: {', '.join(row.get('fixed') or [])}"]))[:4000]
        advisories.append({
            "external_id": external_id, "url": f"https://security.paloaltonetworks.com/{external_id}",
            "title": row.get("title") or external_id, "summary": summary,
            "severity": str(row.get("baseSeverity") or row.get("threatSeverity") or "unknown").upper(),
            "published_at": row.get("date") or row.get("updated"), "cve_ids": cves,
            "vendors": ["paloalto"], "products": row.get("product") or [], "is_kev": False,
            "exploitation_status": "unknown", "domain": "OT", "raw": row,
            "content_hash": sha256_json(row),
        })
    return advisories, [], {"paloalto": status}


def fetch_nvd_ics(limit: int = 200) -> tuple[list[dict], list[dict], dict]:
    """Fetch free NVD CVEs matching ICS, marked OT without changing canonical NVD rows."""
    nvd_key = get_env("NVD_API_KEY")
    try:
        status, data = http_get_json(SOURCES["nvd_ics"]["url"].replace("2000", str(min(limit, 2000))), headers={"apiKey": nvd_key} if nvd_key else {})
    except HTTPError as e:
        return [], [], {"nvd_ics": e.status}
    advisories, vulns = [], []
    for item in data.get("vulnerabilities", []) or []:
        cve = item.get("cve") or item
        normalized = normalize_nvd(cve)
        normalized["domain"] = "OT"
        normalized["content_hash"] = sha256_json(normalized["raw"])
        advisories.append(normalized)
        vuln = normalize_nvd_to_vuln(cve)
        if vuln.get("cve_id"):
            vulns.append(vuln)
    return advisories, vulns, {"nvd_ics": status}


# Slugs in DB are different from the CLI source names
SOURCE_SLUGS = {
    "KEV": "cisa_kev",
    "EPSS": "epss",
    "GHSA": "ghsa",
    "NVD": "nvd",
    "MSRC": "msrc",
    "ABB": "abb_psirt",
    "ABB_CSAF": "abb_csaf",
    "SIEMENS": "siemens",
    "ROCKWELL": "rockwell",
    "CERT_VDE": "cert_vde",
    "FORTINET": "fortinet",
    "CISCO": "cisco_psirt",
    "PALOALTO": "paloalto",
    "CISA_ICS": "cisa_ics",
    "MOXA": "moxa",
    "NVD_ICS": "nvd_ics",
}

FETCHERS = {
    "KEV": fetch_kev,
    "EPSS": fetch_epss,
    "GHSA": fetch_ghsa,
    "NVD": fetch_nvd,
    "MSRC": fetch_msrc,
    "ABB": fetch_abb_psirt,
    "ABB_CSAF": fetch_abb_csaf,
    "SIEMENS": lambda limit=None: fetch_ot_csaf("siemens", limit),
    "ROCKWELL": lambda limit=None: fetch_ot_rss("rockwell", limit),
    "CERT_VDE": lambda limit=None: fetch_ot_rss("cert_vde", limit),
    "FORTINET": lambda limit=None: fetch_ot_rss("fortinet", limit),
    "CISCO": fetch_cisco_psirt,
    "PALOALTO": fetch_paloalto,
    "CISA_ICS": fetch_cisa_ics,
    "MOXA": fetch_moxa,
    "NVD_ICS": fetch_nvd_ics,
}

# ----------------------------- upsert helpers -----------------------------

def upsert_advisories(source_slug: str, advisories: list[dict]) -> int:
    """Batch upsert advisories for a source. Returns count upserted."""
    src_id = sb_get_source_id_cached(PROJECT_REF, source_slug)
    if not src_id or not advisories:
        return 0
    rows = []
    for a in advisories:
        rows.append({
            "source_id": src_id,
            "external_id": a["external_id"],
            "url": a.get("url"),
            "title": a.get("title"),
            "summary": a.get("summary"),
            "severity": a.get("severity", "unknown"),
            "published_at": a.get("published_at"),
            "raw": a.get("raw") or {},
            "content_hash": a["content_hash"],
            "cve_ids": a.get("cve_ids") or [],
            "vendors": a.get("vendors") or [],
            "products": a.get("products") or [],
            "is_kev": a.get("is_kev", False),
            "exploitation_status": a.get("exploitation_status", "unknown"),
            "domain": a.get("domain", "IT"),
            "last_seen_at": "now()",
        })
    # PostgREST caps at ~1000 rows per request
    total = 0
    for i in range(0, len(rows), 500):
        chunk = rows[i:i+500]
        req = urllib.request.Request(
            sb_url(PROJECT_REF, "/advisories?on_conflict=source_id,external_id"),
            data=json.dumps(chunk).encode(),
            headers={**sb_headers(), "Prefer": "resolution=merge-duplicates,return=minimal"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=60).read()
            total += len(chunk)
        except urllib.error.HTTPError as e:
            print(f"advisory upsert error {e.code}: {e.read().decode()[:300]}", file=sys.stderr)
    return total


def _fetch_existing_vulns(cve_ids: list[str]) -> dict[str, dict]:
    """Fetch existing vulnerability rows for a set of CVEs to preserve boolean flags
    when a later source doesn't carry them. Returns {cve_id: row_dict}.
    """
    out: dict[str, dict] = {}
    if not cve_ids:
        return out
    headers = sb_headers()
    # PostgREST 'in' filter: cve_id=in.(CVE-X,CVE-Y,...)
    # Cap URL length to ~2000 chars → batch by 50 CVEs
    for i in range(0, len(cve_ids), 50):
        chunk = cve_ids[i:i+50]
        quoted = ",".join(f'"{c}"' for c in chunk)
        req = urllib.request.Request(
            sb_url(PROJECT_REF, f"/vulnerabilities?cve_id=in.({quoted})&select=cve_id,is_kev,kev_date_added,exploited_in_wild"),
            headers=headers,
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                for row in json.loads(resp.read()):
                    out[row["cve_id"]] = row
        except urllib.error.HTTPError:
            continue
    return out


def upsert_vulnerabilities(vulns: list[dict]) -> int:
    """Upsert by cve_id (PK). Merge per-source fields, keep richest non-null.

    Pre-fetches existing rows so we preserve is_kev / exploited_in_wild / etc.
    when the incoming patch doesn't carry them.
    """
    if not vulns:
        return 0
    by_cve: dict[str, dict] = {}
    for v in vulns:
        cid = v.get("cve_id")
        if not cid: continue
        cur = by_cve.setdefault(cid, {
            "cve_id": cid,
            "is_kev": False,
            "kev_date_added": None,
            "cvss_v3_score": None, "cvss_v3_vector": None,
            "cvss_v4_score": None,
            "epss_score": None, "epss_percentile": None,
            "exploited_in_wild": False,
            "poc_public": False, "poc_urls": [],
            "description": None,
            "vendors": [], "products": [],
            "refs": [],
        })
        if v.get("is_kev"):
            cur["is_kev"] = True
            cur["kev_date_added"] = v.get("kev_date_added")
        if v.get("cvss_v3_score") is not None and cur["cvss_v3_score"] is None:
            cur["cvss_v3_score"] = v["cvss_v3_score"]
            cur["cvss_v3_vector"] = v.get("cvss_v3_vector")
        if v.get("cvss_v4_score") is not None and cur["cvss_v4_score"] is None:
            cur["cvss_v4_score"] = v["cvss_v4_score"]
        if v.get("epss_score") is not None:
            cur["epss_score"] = v["epss_score"]
            cur["epss_percentile"] = v.get("epss_percentile")
        if v.get("exploited_in_wild"):
            cur["exploited_in_wild"] = True
        if v.get("poc_public") or v.get("poc_urls"):
            cur["poc_public"] = True
            cur["poc_urls"] = sorted(set(cur["poc_urls"] + (v.get("poc_urls") or [])))[:20]
        if v.get("description") and (not cur["description"] or len(v["description"]) > len(cur["description"] or "")):
            cur["description"] = v["description"][:2000]
        cur["vendors"] = sorted(set(cur["vendors"] + (v.get("vendors") or [])))
        cur["products"] = sorted(set(cur["products"] + (v.get("products") or [])))
        for r in (v.get("refs") or []):
            if r not in cur["refs"]:
                cur["refs"].append(r)
        cur["refs"] = cur["refs"][:30]

    rows = list(by_cve.values())

    # Preserve existing flags so subsequent partial-source upserts don't clobber them.
    existing = _fetch_existing_vulns(list(by_cve.keys()))
    for r in rows:
        prev = existing.get(r["cve_id"])
        if prev:
            if r["is_kev"] is False and prev.get("is_kev"):
                r["is_kev"] = True
                r["kev_date_added"] = r["kev_date_added"] or prev.get("kev_date_added")
            if r["exploited_in_wild"] is False and prev.get("exploited_in_wild"):
                r["exploited_in_wild"] = True

    for r in rows:
        r["content_hash"] = sha256_json({k: v for k, v in r.items() if k != "content_hash"})
        r["last_updated_at"] = datetime.now(timezone.utc).isoformat()
    total = 0
    for i in range(0, len(rows), 500):
        chunk = rows[i:i+500]
        req = urllib.request.Request(
            sb_url(PROJECT_REF, "/vulnerabilities?on_conflict=cve_id"),
            data=json.dumps(chunk).encode(),
            headers={**sb_headers(), "Prefer": "resolution=merge-duplicates,return=minimal"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=60).read()
            total += len(chunk)
        except urllib.error.HTTPError as e:
            print(f"vuln upsert error {e.code}: {e.read().decode()[:300]}", file=sys.stderr)
    return total


# ----------------------------- main -----------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default="KEV",
                    help="KEV|EPSS|GHSA|NVD|MSRC or comma list or 'all'")
    ap.add_argument("--limit", type=int, default=None,
                    help="Cap items per source (QA)")
    ap.add_argument("--cves", default=None,
                    help="Comma list of CVEs for NVD fetch")
    ap.add_argument("--nvd-since", default=None,
                    help="ISO date for NVD lastModStartDate window (e.g. 2026-07-28)")
    args = ap.parse_args()

    src_choice = args.source.upper()
    sources = list(FETCHERS.keys()) if src_choice == "ALL" else [s.strip().upper() for s in src_choice.split(",")]
    for s in sources:
        if s not in FETCHERS:
            print(f"unknown source: {s}; valid: {list(FETCHERS.keys())}", file=sys.stderr)
            sys.exit(2)

    started = datetime.now(timezone.utc)
    http_statuses: dict[str, int] = {}
    errors: list[str] = []
    adv_count = 0
    vuln_count = 0
    sources_ok = 0

    # Start a delivery_run row
    run_id = ""
    try:
        run_id = sb_record_run(PROJECT_REF, {
            "started_at": started.isoformat(),
            "sources_attempted": len(sources),
        })
    except Exception as e:
        print(f"warning: could not create delivery_run: {e}", file=sys.stderr)

    for src in sources:
        try:
            if src == "NVD":
                kwargs = {"limit": args.limit or 20}
                if args.cves:
                    kwargs["cve_ids"] = [c.strip() for c in args.cves.split(",")]
                elif args.nvd_since:
                    kwargs["last_mod_start"] = f"{args.nvd_since}T00:00:00.000"
                    # NVD rejects far-future end dates; use now + 1 day
                    kwargs["last_mod_end"] = (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000")
                advs, vulns, statuses = FETCHERS[src](**kwargs)
            else:
                advs, vulns, statuses = FETCHERS[src](limit=args.limit) if args.limit else FETCHERS[src]()
            http_statuses.update(statuses)
            if any(s == 200 for s in statuses.values()):
                sources_ok += 1
            n_adv = upsert_advisories(SOURCE_SLUGS[src], advs)
            n_vuln = upsert_vulnerabilities(vulns)
            adv_count += n_adv
            vuln_count += n_vuln
            print(f"[{src}] advisories upserted={n_adv} vulnerabilities upserted={n_vuln} status={statuses}", flush=True)
        except Exception as e:
            tb = traceback.format_exc()
            errors.append(f"{src}: {e}")
            print(f"[{src}] ERROR: {e}\n{tb}", file=sys.stderr)

    finished = datetime.now(timezone.utc)
    try:
        if run_id:
            sb_patch_run(PROJECT_REF, run_id, {
                "finished_at": finished.isoformat(),
                "sources_ok": sources_ok,
                "advisories_new": adv_count,
                "cves_new": vuln_count,
                "http_statuses": http_statuses,
                "errors": errors,
                "briefing_sent": False,
                "briefing_reason": "ingest_only",
            })
    except Exception as e:
        print(f"warning: could not patch delivery_run: {e}", file=sys.stderr)

    print(f"\nDONE run_id={run_id} advisories={adv_count} vulnerabilities={vuln_count} errors={len(errors)}")
    sys.exit(0 if not errors else 0)  # don't fail cron on partial errors


if __name__ == "__main__":
    main()