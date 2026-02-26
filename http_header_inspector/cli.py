from __future__ import annotations

import argparse
import json
import sys
from typing import List

from .core import HeaderResult, inspect_multiple


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="header-inspect",
        description="Fetch HTTP(S) response headers for one or more URLs and highlight security/caching headers.",
    )
    parser.add_argument(
        "urls",
        nargs="+",
        help="URL(s) to inspect (e.g. https://example.com). Scheme is optional; https is assumed if missing.",
    )
    parser.add_argument(
        "--no-follow",
        action="store_true",
        help="Do not follow redirects (by default redirects are followed).",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (text or json, default: text).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Request timeout in seconds (default: 10.0).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="http-header-inspector 0.1.0",
    )
    return parser


def format_text_single(result: HeaderResult) -> str:
    lines: List[str] = []

    lines.append(f"URL: {result.url}")
    if result.error:
        lines.append(f"Error: {result.error}")
        return "\n".join(lines)

    lines.append(f"Final URL: {result.final_url}")
    lines.append(f"Status: {result.status_code} {result.reason}")

    if result.history:
        lines.append("")
        lines.append("Redirect chain:")
        for idx, h in enumerate(result.history, start=1):
            lines.append(f"  {idx}. {h}")

    if result.security_headers:
        lines.append("")
        lines.append("Security headers:")
        for k, v in result.security_headers.items():
            lines.append(f"  {k}: {v}")
    else:
        lines.append("")
        lines.append("Security headers: (none detected)")

    if result.caching_headers:
        lines.append("")
        lines.append("Caching headers:")
        for k, v in result.caching_headers.items():
            lines.append(f"  {k}: {v}")
    else:
        lines.append("")
        lines.append("Caching headers: (none detected)")

    lines.append("")
    lines.append("All headers:")
    for k, v in sorted(result.headers.items(), key=lambda kv: kv[0].lower()):
        lines.append(f"  {k}: {v}")

    return "\n".join(lines)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    follow_redirects = not args.no_follow

    results = inspect_multiple(args.urls, follow_redirects=follow_redirects, timeout=args.timeout)

    if args.format == "json":
        json_data = []
        for r in results:
            json_data.append(
                {
                    "url": r.url,
                    "final_url": r.final_url,
                    "status_code": r.status_code,
                    "reason": r.reason,
                    "history": r.history,
                    "headers": r.headers,
                    "security_headers": r.security_headers,
                    "caching_headers": r.caching_headers,
                    "error": r.error,
                }
            )
        print(json.dumps(json_data, indent=2, ensure_ascii=False))
    else:
        # text output
        for idx, r in enumerate(results):
            if idx > 0:
                print("\n" + "=" * 60 + "\n")
            print(format_text_single(r))


if __name__ == "__main__":
    main()
