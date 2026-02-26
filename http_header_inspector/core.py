from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests


DEFAULT_TIMEOUT = 10.0


@dataclass
class HeaderResult:
    url: str
    final_url: str
    status_code: int
    reason: str
    history: List[str]
    headers: Dict[str, str]
    security_headers: Dict[str, str]
    caching_headers: Dict[str, str]
    error: Optional[str] = None


SECURITY_HEADER_KEYS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

CACHING_HEADER_KEYS = [
    "Cache-Control",
    "Expires",
    "ETag",
    "Last-Modified",
    "Pragma",
]


def normalize_url(url: str) -> str:
    """
    Ensure URL has a scheme; default to https if missing.
    """
    parsed = urlparse(url)
    if not parsed.scheme:
        return "https://" + url
    return url


def fetch_headers(url: str, follow_redirects: bool = True, timeout: float = DEFAULT_TIMEOUT) -> HeaderResult:
    """
    Fetch HTTP(S) headers for a given URL.
    Follows redirects by default and extracts security/caching headers.
    """
    full_url = normalize_url(url)

    try:
        # GET is fine here; we only read headers, and we want redirect history.
        # Requests follows redirects by default when allow_redirects=True.[web:52][web:57][web:63]
        response = requests.get(full_url, allow_redirects=follow_redirects, timeout=timeout)
    except requests.RequestException as exc:
        return HeaderResult(
            url=url,
            final_url=full_url,
            status_code=0,
            reason="Request error",
            history=[],
            headers={},
            security_headers={},
            caching_headers={},
            error=str(exc),
        )

    # Collect redirect chain URLs.[web:52][web:60]
    history_urls = [r.url for r in response.history] if response.history else []

    # requests uses case-insensitive headers, but we want a normal dict for JSON, etc.[web:52]
    headers = {k: v for k, v in response.headers.items()}

    security_headers = {}
    for key in SECURITY_HEADER_KEYS:
        if key in headers:
            security_headers[key] = headers[key]

    caching_headers = {}
    for key in CACHING_HEADER_KEYS:
        if key in headers:
            caching_headers[key] = headers[key]

    return HeaderResult(
        url=url,
        final_url=response.url,
        status_code=response.status_code,
        reason=response.reason,
        history=history_urls,
        headers=headers,
        security_headers=security_headers,
        caching_headers=caching_headers,
        error=None,
    )


def inspect_multiple(urls: list[str], follow_redirects: bool = True, timeout: float = DEFAULT_TIMEOUT) -> list[HeaderResult]:
    """
    Inspect headers for multiple URLs sequentially.
    """
    results: list[HeaderResult] = []
    for u in urls:
        results.append(fetch_headers(u, follow_redirects=follow_redirects, timeout=timeout))
    return results
