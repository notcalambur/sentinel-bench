"""Supabase REST client — minimal surface, only what ingest/diff need."""
import json
import urllib.request
from typing import Any
from urllib.error import HTTPError

from .config import get_env
from .http_client import HTTPError as HTTPGetError


def sb_url(project_ref: str, path: str) -> str:
    return f"https://{project_ref}.supabase.co/rest/v1{path}"


def sb_headers(use_service_role: bool = True) -> dict[str, str]:
    key = ""
    if use_service_role:
        key = get_env("SUPABASE_SERVICE_ROLE_KEY")
    if not key:
        key = get_env("SUPABASE_ANON_KEY") or get_env("PUBLIC_SUPABASE_ANON_KEY")
    return {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "Prefer": "return=minimal",
    }


def _postgrest(path: str, body: Any, *, project_ref: str, prefer: str = "return=minimal") -> Any:
    headers = sb_headers()
    headers["Prefer"] = prefer
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        sb_url(project_ref, path),
        data=data,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
            if not raw or prefer == "return=minimal":
                return None
            return json.loads(raw) if raw else None
    except HTTPError as e:
        body_txt = e.read().decode("utf-8", "ignore")[:500]
        raise HTTPGetError(e.code, path, body_txt) from e


def sb_upsert_advisory(project_ref: str, row: dict) -> bool:
    """Upsert by (source_id, external_id). Returns True if new row."""
    rows = _postgrest(
        "/advisories?on_conflict=source_id,external_id",
        [row],
        project_ref=project_ref,
        prefer="resolution=merge-duplicates,return=minimal",
    )
    # We don't easily know if it was inserted vs updated via minimal return.
    # Use a follow-up count or rely on caller tracking state externally.
    return True


def sb_upsert_vuln(project_ref: str, row: dict) -> bool:
    """Upsert by cve_id (PK)."""
    _postgrest(
        "/vulnerabilities?on_conflict=cve_id",
        [row],
        project_ref=project_ref,
        prefer="resolution=merge-duplicates,return=minimal",
    )
    return True


def sb_record_run(project_ref: str, row: dict) -> str:
    """Insert delivery_runs row, return its id."""
    res = _postgrest(
        "/delivery_runs",
        [row],
        project_ref=project_ref,
        prefer="return=representation",
    )
    if res and isinstance(res, list) and res:
        return res[0]["id"]
    return ""


def sb_patch_run(project_ref: str, run_id: str, patch: dict) -> None:
    """PATCH delivery_runs row by id."""
    headers = sb_headers()
    data = json.dumps(patch).encode("utf-8")
    req = urllib.request.Request(
        sb_url(project_ref, f"/delivery_runs?id=eq.{run_id}"),
        data=data,
        headers=headers,
        method="PATCH",
    )
    try:
        urllib.request.urlopen(req, timeout=30).read()
    except HTTPError as e:
        body = e.read().decode("utf-8", "ignore")[:300]
        raise HTTPGetError(e.code, f"/delivery_runs?id=eq.{run_id}", body) from e


def sb_get_source_id(project_ref: str, slug: str) -> str | None:
    """Lookup source UUID by slug. Cached per process via simple dict."""
    headers = sb_headers()
    req = urllib.request.Request(
        sb_url(project_ref, f"/sources?slug=eq.{slug}&select=id"),
        headers=headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            rows = json.loads(resp.read())
            return rows[0]["id"] if rows else None
    except (HTTPError, KeyError, IndexError):
        return None


# Tiny in-process cache
_SOURCE_ID_CACHE: dict[tuple[str, str], str] = {}


def sb_get_source_id_cached(project_ref: str, slug: str) -> str | None:
    key = (project_ref, slug)
    if key not in _SOURCE_ID_CACHE:
        _SOURCE_ID_CACHE[key] = sb_get_source_id(project_ref, slug)
    return _SOURCE_ID_CACHE[key]