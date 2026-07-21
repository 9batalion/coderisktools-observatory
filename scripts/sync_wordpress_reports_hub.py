#!/usr/bin/env python3
"""Synchronize the bounded GitHub Reports hub block into the WordPress page."""
from __future__ import annotations

import argparse
import base64
import html
import json
import os
import sys
import urllib.parse
import urllib.request

START = "<!-- crt-publication-hub-start -->"
END = "<!-- crt-publication-hub-end -->"
DEFAULT_LATEST_JSON = (
    "https://raw.githubusercontent.com/9batalion/"
    "coderisktools-observatory-reports/main/public/weekly/latest.json"
)


def request(url: str, *, method: str = "GET", payload: bytes | None = None, auth: tuple[str, str] | None = None):
    headers = {"Cache-Control": "no-cache", "Pragma": "no-cache"}
    if auth:
        authorization_value = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        headers["Authorization"] = f"Basic {authorization_value}"
    if payload is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=payload, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=30) as response:
        return response.status, json.loads(response.read())


def get_latest_url(latest_json_url: str) -> str:
    status, payload = request(latest_json_url)
    if status != 200 or not isinstance(payload, dict):
        raise RuntimeError("latest.json did not return an object")
    report_path = payload.get("report_path")
    week = payload.get("week")
    if not isinstance(report_path, str) or not report_path.startswith("/weekly/"):
        raise RuntimeError("latest.json has no safe weekly report_path")
    if not isinstance(week, str) or not week or any(c in week for c in "/?#"):
        raise RuntimeError("latest.json has no safe week")
    return "https://9batalion.github.io/coderisktools-observatory-reports" + report_path


def render_block(latest_url: str) -> str:
    safe_url = html.escape(latest_url, quote=True)
    return f'''{START}
<section class="crt-publication-hub" aria-labelledby="crt-publication-hub-title" style="margin:30px 0;padding:24px;background:#0b1118;border:1px solid #294158;border-radius:14px;color:#dbe7f3">
<p style="margin:0 0 8px;color:#7dd3fc;font:700 12px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.08em;text-transform:uppercase">PUBLIC PUBLICATION HUB</p>
<h3 id="crt-publication-hub-title" style="margin:0 0 10px;color:#f8fafc">Read the latest review and reproduce the source</h3>
<p style="margin:0 0 16px;line-height:1.65">The WordPress page is the editorial entry point. The immutable report bytes, weekly index and source history live in the public reports repository and are published through its reviewed workflow.</p>
<div style="display:flex;flex-wrap:wrap;gap:10px;margin:0 0 16px"><a href="{safe_url}" style="display:inline-block;padding:11px 15px;border-radius:8px;background:#f2c98c;color:#111827;font-weight:700">Open latest named review</a><a href="https://github.com/9batalion/coderisktools-observatory-reports" style="display:inline-block;padding:11px 15px;border-radius:8px;background:#1a2634;border:1px solid #58708a;color:#f8fafc;font-weight:700">Open source repository</a></div>
<ul style="margin:0;padding-left:20px;line-height:1.7"><li>public artifacts are reviewed through pull requests;</li><li>exact source commits, manifests and checksums remain reproducible;</li><li>raw findings, secrets and private operator evidence are not published.</li></ul>
</section>
{END}'''


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--latest-json-url", default=DEFAULT_LATEST_JSON)
    parser.add_argument("--page-id", default=os.getenv("WP_PAGE_ID", "1217"))
    args = parser.parse_args()

    api_base = os.environ.get("WP_API_BASE_URL", "").rstrip("/")
    username = os.environ.get("WP_USERNAME", "")
    auth_value = os.environ.get("WP_APP_AUTH", "")
    if not api_base or not username or not auth_value:
        raise SystemExit("WP_API_BASE_URL, WP_USERNAME and WP_APP_AUTH are required")
    page_url = f"{api_base}/wp/v2/pages/{urllib.parse.quote(str(args.page_id))}?context=edit"
    _, page = request(page_url, auth=(username, auth_value))
    raw = page.get("content", {}).get("raw")
    if not isinstance(raw, str) or raw.count(START) != 1 or raw.count(END) != 1:
        raise SystemExit("page must contain exactly one publication-hub marker pair")
    latest_url = get_latest_url(args.latest_json_url)
    a, b = raw.index(START), raw.index(END) + len(END)
    candidate = raw[:a] + render_block(latest_url) + raw[b:]
    print(json.dumps({"page_id": page.get("id"), "latest_url": latest_url, "candidate_chars": len(candidate), "dry_run": args.dry_run}, sort_keys=True))
    if raw == candidate:
        print(json.dumps({"readback": "UNCHANGED", "write_status": None, "page_id": page.get("id")}, sort_keys=True))
        return 0
    if args.dry_run:
        return 0
    status, updated = request(page_url, method="POST", payload=json.dumps({"content": candidate}).encode(), auth=(username, auth_value))
    if status not in (200, 201):
        raise SystemExit(f"unexpected WordPress write status: {status}")
    _, readback = request(page_url, auth=(username, auth_value))
    if readback.get("content", {}).get("raw") != candidate:
        raise SystemExit("WordPress raw content readback mismatch")
    print(json.dumps({"write_status": status, "readback": "PASS", "page_id": updated.get("id")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"HTTP error: {exc.code}")
