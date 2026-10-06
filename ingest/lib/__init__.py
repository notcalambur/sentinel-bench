"""Shared lib for sentinel-bench ingest/diff."""
from .config import SOURCES, get_env, project_root
from .http_client import http_get, http_get_json, HTTPError
from .hash import sha256_json, content_hash
from .supabase import sb_headers, sb_url, sb_upsert_advisory, sb_upsert_vuln, sb_record_run, sb_get_source_id_cached, sb_patch_run
from .normalize import (
    normalize_kev,
    normalize_epss, normalize_epss_to_vuln,
    normalize_ghsa, normalize_ghsa_to_vuln,
    normalize_nvd, normalize_nvd_to_vuln,
    normalize_msrc,
)
from .score import compute_score, score_breakdown

__all__ = [
    "SOURCES", "get_env", "project_root",
    "http_get", "http_get_json", "HTTPError",
    "sha256_json", "content_hash",
    "sb_headers", "sb_url", "sb_upsert_advisory", "sb_upsert_vuln", "sb_record_run", "sb_get_source_id_cached", "sb_patch_run",
    "normalize_kev",
    "normalize_epss", "normalize_epss_to_vuln",
    "normalize_ghsa", "normalize_ghsa_to_vuln",
    "normalize_nvd", "normalize_nvd_to_vuln",
    "normalize_msrc",
    "compute_score", "score_breakdown",
]