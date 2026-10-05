"""Prune advisories older than N days from their last_seen_at.

Usage:  python3 -m ingest.prune --days 90 [--dry-run]
"""
import argparse
import json
import urllib.parse
import urllib.request
from urllib.error import HTTPError

from ingest.lib.http_client import HTTPError as HTTPGetError
from ingest.lib.supabase import sb_headers

from ingest.ingest import PROJECT_REF


def _postgrest(path: str, *, method: str = "GET") -> tuple[int, str]:
    req = urllib.request.Request(
        f"https://{PROJECT_REF}.supabase.co/rest/v1{path}",
        headers={**sb_headers(), "Prefer": "return=minimal"},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", "ignore")
    except HTTPError as e:
        return e.code, e.read().decode("utf-8", "ignore")[:300]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=90)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    # ponytail: SELECT-then-DELETE pattern keeps the operation explicit; switch to
    # a single DELETE with Prefer:count=exact when batch size grows past a few thousand.
    # PostgREST can't parse `now()-interval`; the days filter is applied client-side.
    status, body = _postgrest("/advisories?select=id,last_seen_at")
    if status != 200:
        raise SystemExit(f"prune select failed: {status} {body}")
    from datetime import datetime, timedelta, timezone
    cutoff = datetime.now(timezone.utc) - timedelta(days=args.days)
    rows = json.loads(body or "[]")
    stale_ids = [r["id"] for r in rows if r.get("last_seen_at") and datetime.fromisoformat(r["last_seen_at"].replace("Z", "+00:00")) < cutoff]
    print(f"[prune] candidates last_seen_at < {args.days}d: {len(stale_ids)}")
    if args.dry_run or not stale_ids:
        return 0
    # Delete in batches to avoid request-size caps; 500 rows per round is safe.
    deleted = 0
    for i in range(0, len(stale_ids), 500):
        chunk = stale_ids[i : i + 500]
        ids = ",".join(quote(r) for r in chunk)
        delete_qs = urllib.parse.urlencode({"id": f"in.({ids})"})
        status, body = _postgrest(f"/advisories?{delete_qs}", method="DELETE")
        if status >= 300:
            raise SystemExit(f"prune delete failed: {status} {body}")
        deleted += len(chunk)
    print(f"[prune] deleted={deleted} older_than={args.days}d")
    return 0


def quote(v: str) -> str:
    return '"' + v.replace('"', '\\"') + '"'


if __name__ == "__main__":
    raise SystemExit(main())