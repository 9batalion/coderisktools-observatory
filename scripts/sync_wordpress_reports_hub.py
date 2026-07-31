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
RANKING_START = "<!-- crt-ranking-coverage-start -->"
RANKING_END = "<!-- crt-ranking-coverage-end -->"
LEGACY_RANKING_END = "<!-- legacy-evidence-ranking-removed-2026-07-27: replaced by single report-card table above -->"
DEFAULT_LATEST_JSON = (
    "https://raw.githubusercontent.com/9batalion/"
    "coderisktools-observatory-reports/main/public/rankings/latest.json"
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
    if not isinstance(report_path, str) or not (report_path.startswith("/weekly/") or report_path.startswith("/rankings/")):
        raise RuntimeError("latest.json has no safe report_path")
    if not isinstance(week, str) or not week or any(c in week for c in "/?#"):
        raise RuntimeError("latest.json has no safe week")
    return "https://9batalion.github.io/coderisktools-observatory-reports" + report_path


def get_coverage_report(latest_url: str) -> dict:
    report_url = latest_url.rstrip("/") + "/report.json"
    status, payload = request(report_url)
    if status != 200 or not isinstance(payload, dict):
        raise RuntimeError("ranking report.json did not return an object")
    if payload.get("schema") != "coderisktools.observatory.popularity-ranking.v1":
        raise RuntimeError("latest report is not the verified popularity-ranking schema")
    publication = payload.get("publication")
    if publication != {
        "firewall_results": "NOT_PUBLISHED",
        "purpose": "POPULARITY_COHORT_SCAN_COVERAGE",
        "raw_findings": "NOT_PUBLISHED",
        "security_ranking": False,
    }:
        raise RuntimeError("ranking publication boundary is not the non-security coverage contract")
    entries = payload.get("entries")
    if not isinstance(entries, list) or len(entries) != 15:
        raise RuntimeError("ranking report must contain exactly 15 entries")
    return payload


def render_coverage_block(report_url: str, report: dict) -> str:
    rows = []
    for entry in report["entries"]:
        repo = html.escape(entry["repository"])
        repo_url = html.escape(entry["repository_url"], quote=True)
        sha = html.escape(entry["head_sha"][:12])
        status = html.escape(entry["scan_status"])
        stars = f'{entry["stars"]:,}'
        rows.append(f'<tr><td>{entry["rank"]}</td><td><a href="{repo_url}">{repo}</a></td><td>{stars}</td><td><code>{sha}</code></td><td>{status}</td></tr>')
    safe_report = html.escape(report_url, quote=True)
    week = html.escape(report["week"])
    return f'''{RANKING_START}
<section class="crt-ranking-coverage" aria-labelledby="crt-ranking-coverage-title">
<h2 id="crt-ranking-coverage-title">Popularity Cohort &amp; Scan Coverage</h2>
<p><strong>2026-W30 coverage index:</strong> 15 public repositories selected by GitHub popularity. This is not a vulnerability ranking, security score, certification or endorsement.</p>
<table><thead><tr><th>Popularity rank</th><th>Repository</th><th>Stars at snapshot</th><th>Reviewed commit</th><th>Scan status</th></tr></thead><tbody>{"".join(rows)}</tbody></table>
<p>Raw findings, secrets, paths, scores and security conclusions are not published. <a href="{safe_report}">Open the immutable report JSON</a> and reproduce the source from the reports repository.</p>
</section>
{RANKING_END}'''


def render_block(latest_url: str) -> str:
    safe_url = html.escape(latest_url, quote=True)
    return f'''{START}
<section class="crt-publication-hub" aria-labelledby="crt-publication-hub-title" style="margin:30px 0;padding:24px;background:#0b1118;border:1px solid #294158;border-radius:14px;color:#dbe7f3">
<p style="margin:0 0 8px;color:#7dd3fc;font:700 12px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.08em;text-transform:uppercase">PUBLIC PUBLICATION HUB</p>
<h3 id="crt-publication-hub-title" style="margin:0 0 10px;color:#f8fafc">Read the latest coverage index and reproduce the source</h3>
<p style="margin:0 0 16px;line-height:1.65">The WordPress page is the editorial entry point. The immutable report bytes, weekly index and source history live in the public reports repository and are published through its reviewed workflow.</p>
<div style="display:flex;flex-wrap:wrap;gap:10px;margin:0 0 16px"><a href="{safe_url}" style="display:inline-block;padding:11px 15px;border-radius:8px;background:#f2c98c;color:#111827;font-weight:700">Open latest coverage index</a><a href="https://github.com/9batalion/coderisktools-observatory-reports" style="display:inline-block;padding:11px 15px;border-radius:8px;background:#1a2634;border:1px solid #58708a;color:#f8fafc;font-weight:700">Open source repository</a></div>
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
    if not isinstance(raw, str):
        raise SystemExit("page content raw is missing")
    latest_url = get_latest_url(args.latest_json_url)
    report = get_coverage_report(latest_url)
    hub = render_block(latest_url)
    if raw.count(START) == 1 and raw.count(END) == 1:
        a, b = raw.index(START), raw.index(END) + len(END)
        candidate = raw[:a] + hub + raw[b:]
    elif raw.count('<section class="crt-publication-hub"') == 1 and raw.count('</section>') >= 1:
        a = raw.index('<section class="crt-publication-hub"')
        b = raw.index('</section>', a) + len('</section>')
        candidate = raw[:a] + hub + raw[b:]
    elif raw.count(RANKING_START) == 1 and raw.count(RANKING_END) == 1:
        a = raw.index(RANKING_START)
        candidate = raw[:a] + hub + "\n\n" + raw[a:]
    else:
        raise SystemExit("page has no safe publication-hub boundary")
    coverage = render_coverage_block(latest_url, report)
    if RANKING_START in candidate or RANKING_END in candidate:
        if candidate.count(RANKING_START) != 1 or candidate.count(RANKING_END) != 1:
            raise SystemExit("page must contain exactly one ranking coverage marker pair")
        ra, rb = candidate.index(RANKING_START), candidate.index(RANKING_END) + len(RANKING_END)
        candidate = candidate[:ra] + coverage + candidate[rb:]
    elif LEGACY_RANKING_END in candidate:
        heading = "<h2>Vulnerability Summary &amp; Repository Ranking</h2>"
        ra, rb = candidate.find(heading), candidate.find(LEGACY_RANKING_END)
        if ra < 0 or rb <= ra:
            raise SystemExit("legacy ranking boundary is incomplete")
        candidate = candidate[:ra] + coverage + "\n\n" + candidate[rb:]
    else:
        raise SystemExit("page has neither ranking coverage markers nor legacy ranking boundary")
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
