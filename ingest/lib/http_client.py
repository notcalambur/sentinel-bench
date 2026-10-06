"""HTTP helpers with retries, timeouts, rate-limit awareness."""
import json
import time
import urllib.error
import urllib.request
from typing import Any

DEFAULT_TIMEOUT = 30
DEFAULT_RETRIES = 3
BACKOFF_BASE = 1.5  # seconds


class HTTPError(Exception):
    def __init__(self, status: int, url: str, body: str = ""):
        self.status = status
        self.url = url
        self.body = body
        super().__init__(f"HTTP {status} on {url}: {body[:200]}")


def http_get(
    url: str,
    headers: dict | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
) -> tuple[int, bytes]:
    """GET with retry+backoff. Returns (status, body_bytes). Raises on persistent failure."""
    hdrs = {
        "User-Agent": "sentinel-bench/1.0 (+https://github.com/iamtweaks/sentinel-bench)",
        "Accept": "application/json",
        **(headers or {}),
    }
    last_err: Exception | None = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            # 4xx are caller errors — don't retry 400/403/404
            if 400 <= e.code < 500 and e.code not in (408, 429):
                raise HTTPError(e.code, url, e.read().decode("utf-8", "ignore")[:300]) from e
            last_err = HTTPError(e.code, url, e.read().decode("utf-8", "ignore")[:300])
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last_err = e
        if attempt < retries - 1:
            time.sleep(BACKOFF_BASE ** attempt)
    raise HTTPError(0, url, str(last_err)[:300])


def http_get_json(url: str, headers: dict | None = None, **kw) -> tuple[int, Any]:
    status, body = http_get(url, headers=headers, **kw)
    try:
        return status, json.loads(body)
    except json.JSONDecodeError as e:
        raise HTTPError(status, url, f"JSON decode error: {e}") from e