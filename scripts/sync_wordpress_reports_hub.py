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
NEXT_COHORT = [
    ("moby/moby", 71966, "partial"),
    ("chrislgarry/Apollo-11", 71803, "complete"),
    ("NationalSecurityAgency/ghidra", 71799, "partial"),
    ("juliangarnier/anime", 71747, "not_started"),
    ("protocolbuffers/protobuf", 71682, "not_started"),
    ("ComposioHQ/awesome-claude-skills", 71671, "not_started"),
    ("OpenBB-finance/OpenBB", 71339, "not_started"),
    ("nektos/act", 71310, "not_started"),
    ("binary-husky/gpt_academic", 71179, "not_started"),
    ("toeverything/AFFiNE", 71125, "not_started"),
    ("microsoft/ai-agents-for-beginners", 71100, "not_started"),
    ("Leonxlnx/taste-skill", 70923, "not_started"),
    ("datawhalechina/hello-agents", 70426, "not_started"),
    ("swiftlang/swift", 70212, "not_started"),
    ("ansible/ansible", 70201, "not_started"),
]
REPORTS_PER_PAGE = 50
STATUS_LABELS = {"complete": "COMPLETE", "partial": "PARTIAL", "not_started": "NOT STARTED"}
NEXT_COHORT_SHA = {
    "moby/moby": "6719bc3c8d675b3ac60a2fd78c630a066177e20d",
    "chrislgarry/Apollo-11": "911e5c0283c629c50cb97666f34065e8c07d71a5",
    "NationalSecurityAgency/ghidra": "264130231b130b5fd8fd4ac85f1e7f5a8d1af252",
    "juliangarnier/anime": "2c9cf8ea00329f6768c7d7902252ed977d75ce42",
    "protocolbuffers/protobuf": "0e436a47e854982213b4c9a72ca7f48c29bd7b88",
    "ComposioHQ/awesome-claude-skills": "be2a406907dbc61b73e6827ded415c96139d13a2",
    "OpenBB-finance/OpenBB": "3e071fcc2cd9f891cac6040ae60296dba76dab46",
    "nektos/act": "4f411281417e88660bea1c1a1749aa71ae0bd60f",
    "binary-husky/gpt_academic": "d6bde0fa54373309bd05823a49bda8da019d2c77",
    "toeverything/AFFiNE": "fdfb6df8260577efd03ca3679e3310702a8f69e0",
    "microsoft/ai-agents-for-beginners": "15ad10ca60577b75199c1ba828887ab7e66bac87",
    "Leonxlnx/taste-skill": "e988add20dab0fa97d7a76781c48961c8184288e",
    "datawhalechina/hello-agents": "f8227af2efc4a244763d379d78d9e76fc7b35943",
    "swiftlang/swift": "4ef9a5286c51308858f6836cda1514edc0921358",
    "ansible/ansible": "2d8c74aa7ae5726bd47da230ff3cf45821c168c8",
}
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


def format_observation_counts(entry: dict) -> tuple[str, str, str, str, str]:
    counts = entry.get("observation_counts")
    if counts is None:
        return ("—", "—", "—", "—", "—")
    return tuple(str(counts[key]) for key in ("critical", "high", "medium", "low", "total"))


def render_coverage_block(report_url: str, report: dict) -> str:
    combined = []
    for entry in report["entries"]:
        critical, high, medium, low, total = format_observation_counts(entry)
        combined.append({
            "number": entry["rank"],
            "repository": entry["repository"],
            "repository_url": entry["repository_url"],
            "stars": entry["stars"],
            "head_sha": entry["head_sha"],
            "status": entry["scan_status"].upper().replace("_", " "),
            "counts": (critical, high, medium, low, total),
        })
    for number, (repository, stars, status) in enumerate(NEXT_COHORT, start=16):
        combined.append({
            "number": number,
            "repository": repository,
            "repository_url": f"https://github.com/{repository}",
            "stars": stars,
            "head_sha": NEXT_COHORT_SHA[repository],
            "status": STATUS_LABELS[status],
            "counts": ("—", "—", "—", "—", "—"),
        })
    if len(combined) > REPORTS_PER_PAGE:
        raise RuntimeError(f"report page exceeds {REPORTS_PER_PAGE} rows")
    if [entry["number"] for entry in combined] != list(range(1, len(combined) + 1)):
        raise RuntimeError("report numbering must be continuous")
    rows = []
    for entry in combined:
        repo = html.escape(entry["repository"])
        repo_url = html.escape(entry["repository_url"], quote=True)
        sha = html.escape(entry["head_sha"][:12])
        status = html.escape(entry["status"])
        stars = f'{entry["stars"]:,}'
        critical, high, medium, low, total = entry["counts"]
        rows.append(f'<tr><td>{entry["number"]}</td><td><a href="{repo_url}">{repo}</a></td><td>{stars}</td><td><code>{sha}</code></td><td>{status}</td><td>{critical}</td><td>{high}</td><td>{medium}</td><td>{low}</td><td>{total}</td></tr>')
    safe_report = html.escape(report_url, quote=True)
    return f'''{RANKING_START}
<section class="crt-ranking-coverage" aria-labelledby="crt-ranking-coverage-title">
<h2 id="crt-ranking-coverage-title">Repository Reports &amp; Scan Coverage</h2>
<p><strong>Reports 1–30:</strong> one continuous register of public repositories selected by GitHub popularity. This is not a vulnerability ranking, security score, certification, recommendation, or endorsement.</p>
<div class="crt-report-table-scroll" style="overflow-x:auto;-webkit-overflow-scrolling:touch"><table><thead><tr><th>Report</th><th>Repository</th><th>Stars at snapshot</th><th>Reviewed commit</th><th>Scan status</th><th>Critical observations</th><th>High observations</th><th>Medium observations</th><th>Low observations</th><th>Total observations</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div>
<p>Page 1 contains reports 1–30. A report page is limited to {REPORTS_PER_PAGE} rows; reports 51 and later will continue on the next page. An em dash means that aggregate counts have not been published in the immutable report yet; it never means zero.</p>
<p>Severity counts are scanner-rule observations in the tested scope, not confirmed vulnerabilities. Raw findings, secret values, paths, snippets, scores, and security conclusions are not published. <a href="{safe_report}">Open the immutable coverage report JSON</a>.</p>
<h3>Scanner and scan scope</h3>
<p><strong>Primary scanner:</strong> CodeRiskTools Scanner <code>3.1.3</code> from <a href="https://github.com/9batalion/coderisktools-scanner">9batalion/coderisktools-scanner</a>, pinned to exact source commit <code>c1698b297e6200313276c8c2ef8e00a40ee9aa42</code>.</p>
<p><strong>Supporting tools:</strong> Git for exact-SHA checkout and provenance; Python for bounded orchestration, sharding, aggregation, deduplication checks, and checksums. Trivy, Gitleaks, OSV-Scanner, and other scanner engines were not used. Target repository code was never executed; repositories were treated as data.</p>
<p>Reports 16–30 continue the same register after reports 1–15. Each repository begins with default-branch, exact-SHA, license, and checkout-completeness readback. A status of <strong>NOT STARTED</strong> is not a clean result.</p>
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
