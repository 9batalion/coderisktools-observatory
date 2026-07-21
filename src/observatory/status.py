"""Privacy-safe static status artifact generation."""

from __future__ import annotations

import html
import json
import re
from pathlib import Path

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_TIME_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


def _count(value, field):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def _timestamp(value, field):
    if value is not None and (not isinstance(value, str) or not _TIME_RE.fullmatch(value)):
        raise ValueError(f"{field} must be an UTC timestamp or null")
    return value


def build_status(*, generated_at, build_sha, last_publication, reports, digests,
                 retractions, partial_scans, feed_status, self_scan_decision,
                 self_scan_findings, benchmark_passed):
    if not isinstance(build_sha, str) or not _SHA_RE.fullmatch(build_sha):
        raise ValueError("build_sha must be a full lowercase commit SHA")
    _timestamp(generated_at, "generated_at")
    _timestamp(last_publication, "last_publication")
    if feed_status not in {"healthy", "degraded", "unknown"}:
        raise ValueError("invalid feed_status")
    if self_scan_decision not in {"PUBLISH", "HOLD", "REJECT"}:
        raise ValueError("invalid self_scan_decision")
    if not isinstance(benchmark_passed, bool):
        raise ValueError("benchmark_passed must be boolean")
    return {
        "schema_version": "1.0",
        "generated_at": generated_at,
        "last_build_sha": build_sha,
        "last_publication": last_publication,
        "counts": {
            "reports": _count(reports, "reports"),
            "digests": _count(digests, "digests"),
            "retractions": _count(retractions, "retractions"),
            "partial_scans": _count(partial_scans, "partial_scans"),
        },
        "feeds": {"status": feed_status},
        "self_scan": {
            "decision": self_scan_decision,
            "finding_count": _count(self_scan_findings, "self_scan_findings"),
        },
        "benchmark": {"passed": benchmark_passed},
    }


def render_status_html(status):
    counts = status["counts"]
    self_scan = status["self_scan"]
    benchmark = status["benchmark"]
    values = {
        "generated_at": html.escape(status["generated_at"]),
        "build_sha": html.escape(status["last_build_sha"]),
        "last_publication": html.escape(status["last_publication"] or "none"),
        "reports": counts["reports"],
        "digests": counts["digests"],
        "retractions": counts["retractions"],
        "partial_scans": counts["partial_scans"],
        "feed_status": html.escape(status["feeds"]["status"]),
        "self_scan_decision": html.escape(self_scan["decision"]),
        "self_scan_findings": self_scan["finding_count"],
        "benchmark": "PASS" if benchmark["passed"] else "FAIL",
    }
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Observatory status</title>
<style>body{{font:16px system-ui,sans-serif;max-width:760px;margin:3rem auto;padding:0 1rem;color:#17202a}}main{{border:1px solid #d7dde3;border-radius:12px;padding:1.5rem}}dt{{font-weight:700;margin-top:.8rem}}dd{{margin:.15rem 0 0}}code{{font-size:.85em;overflow-wrap:anywhere}}</style></head>
<body><main><h1>Observatory status</h1><dl>
<dt>Generated</dt><dd>{generated_at}</dd><dt>Last build</dt><dd><code>{build_sha}</code></dd><dt>Last publication</dt><dd>{last_publication}</dd>
<dt>Reports</dt><dd>{reports}</dd><dt>Digests</dt><dd>{digests}</dd><dt>Retractions</dt><dd>{retractions}</dd><dt>Partial scans</dt><dd>{partial_scans}</dd>
<dt>Feeds</dt><dd>{feed_status}</dd><dt>Self-scan</dt><dd>{self_scan_decision} ({self_scan_findings} findings)</dd><dt>Benchmark</dt><dd>{benchmark}</dd>
</dl></main></body></html>
""".format(**values)


def write_status_page(output_dir: Path, status):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    status_path = output_dir / "status.json"
    html_path = output_dir / "index.html"
    status_path.write_text(json.dumps(status, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    html_path.write_text(render_status_html(status), encoding="utf-8")
    return str(status_path), str(html_path)
