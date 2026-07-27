"""Privacy-safe static status artifact generation."""

from __future__ import annotations

import html
import json
import re
from pathlib import Path

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_TIME_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_SEVERITIES = ("critical", "high", "medium", "low", "unknown")


def _count(value, field):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def _timestamp(value, field):
    if value is not None and (not isinstance(value, str) or not _TIME_RE.fullmatch(value)):
        raise ValueError(f"{field} must be an UTC timestamp or null")
    return value


def _safe_text(value, field):
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{field} must be a non-empty safe string")
    return value


def _severity_counts(findings):
    counts = {severity: 0 for severity in _SEVERITIES}
    if not isinstance(findings, list):
        return counts
    for finding in findings:
        severity = finding.get("severity") if isinstance(finding, dict) else None
        severity = severity.lower() if isinstance(severity, str) else "unknown"
        if severity not in counts:
            severity = "unknown"
        counts[severity] += 1
    return counts


def _ranking_row(data):
    findings = data.get("findings") if isinstance(data, dict) else []
    counts = _severity_counts(findings)
    target = data.get("target") if isinstance(data.get("target"), dict) else {}
    scan = data.get("scan") if isinstance(data.get("scan"), dict) else {}
    repository = data.get("repository_name") or data.get("repository_url") or "unknown"
    target_sha = target.get("resolved_sha") or scan.get("target_sha") or "0" * 40
    if not isinstance(target_sha, str) or not _SHA_RE.fullmatch(target_sha):
        target_sha = "0" * 40
    total = sum(counts.values())
    score = counts["critical"] * 1000 + counts["high"] * 100 + counts["medium"] * 10 + counts["low"]
    return {
        "repository": _safe_text(str(repository), "repository"),
        "repository_url": data.get("repository_url") if isinstance(data.get("repository_url"), str) else "",
        "target_sha": target_sha,
        "scan_status": scan.get("status") if scan.get("status") in {"complete", "partial", "failed"} else "unknown",
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"],
        "unknown": counts["unknown"],
        "total": total,
        "score": score,
    }


def _validate_ranking(ranking):
    if ranking is None:
        return []
    if not isinstance(ranking, list):
        raise ValueError("vulnerability_ranking must be a list")
    cleaned = []
    allowed = {"repository", "repository_url", "target_sha", "scan_status", "critical", "high", "medium", "low", "unknown", "total", "score"}
    for row in ranking:
        if not isinstance(row, dict) or set(row) != allowed:
            raise ValueError("invalid vulnerability ranking row")
        cleaned.append({
            "repository": _safe_text(row["repository"], "repository"),
            "repository_url": row["repository_url"] if isinstance(row["repository_url"], str) else "",
            "target_sha": row["target_sha"] if isinstance(row["target_sha"], str) and _SHA_RE.fullmatch(row["target_sha"]) else "0" * 40,
            "scan_status": row["scan_status"] if row["scan_status"] in {"complete", "partial", "failed", "unknown"} else "unknown",
            "critical": _count(row["critical"], "critical"),
            "high": _count(row["high"], "high"),
            "medium": _count(row["medium"], "medium"),
            "low": _count(row["low"], "low"),
            "unknown": _count(row["unknown"], "unknown"),
            "total": _count(row["total"], "total"),
            "score": _count(row["score"], "score"),
        })
    return cleaned


def build_status(*, generated_at, build_sha, last_publication, reports, digests,
                 retractions, partial_scans, feed_status, self_scan_decision,
                 self_scan_findings, benchmark_passed, publication_scope="unknown",
                 vulnerability_ranking=None):
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
    if publication_scope not in {"unknown", "empty", "synthetic", "real", "mixed"}:
        raise ValueError("invalid publication_scope")
    return {
        "schema_version": "1.0",
        "generated_at": generated_at,
        "last_build_sha": build_sha,
        "last_publication": last_publication,
        "publication_scope": publication_scope,
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
        "vulnerability_ranking": _validate_ranking(vulnerability_ranking),
    }


def summarize_reports_repository(root: Path):
    """Count only canonical public report artifacts; never inspect operator/."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("reports repository must be a real directory")
    report_root = root / "public" / "reports" / "github"
    weekly_root = root / "public" / "weekly"
    reports = synthetic = real = partial = retractions = digests = 0
    ranking = []
    if report_root.exists():
        if report_root.is_symlink() or not report_root.is_dir():
            raise ValueError("invalid public/reports/github root")
        for path in report_root.glob("*/*/*/*/report.json"):
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"unsafe report artifact: {path}")
            parts = path.relative_to(root).parts
            if len(parts) != 8 or parts[:3] != ("public", "reports", "github"):
                raise ValueError(f"non-canonical report path: {path}")
            data = json.loads(path.read_text(encoding="utf-8"))
            reports += 1
            if isinstance(data, dict) and ("scan" in data or "findings" in data):
                real += 1
                if isinstance(data.get("scan"), dict) and data["scan"].get("status") == "partial":
                    partial += 1
                row = _ranking_row(data)
                if row["total"] > 0:
                    ranking.append(row)
            else:
                synthetic += 1
        retractions = sum(1 for path in report_root.glob("*/*/*/*/retraction.json") if path.is_file() and not path.is_symlink())
    if weekly_root.exists():
        if weekly_root.is_symlink() or not weekly_root.is_dir():
            raise ValueError("invalid public/weekly root")
        digests = sum(1 for path in weekly_root.glob("*/report.json") if path.is_file() and not path.is_symlink())
    scope = "empty" if reports == 0 else ("mixed" if synthetic and real else ("synthetic" if synthetic else "real"))
    ranking.sort(key=lambda row: (-row["critical"], -row["high"], -row["medium"], -row["low"], -row["unknown"], row["repository"]))
    return {"reports": reports, "digests": digests, "retractions": retractions, "partial_scans": partial, "publication_scope": scope, "vulnerability_ranking": ranking}


def render_status_html(status):
    counts = status["counts"]
    self_scan = status["self_scan"]
    benchmark = status["benchmark"]
    values = {
        "generated_at": html.escape(status["generated_at"]),
        "build_sha": html.escape(status["last_build_sha"]),
        "last_publication": html.escape(status["last_publication"] or "none"),
        "publication_scope": html.escape(status["publication_scope"]),
        "reports": counts["reports"],
        "digests": counts["digests"],
        "retractions": counts["retractions"],
        "partial_scans": counts["partial_scans"],
        "feed_status": html.escape(status["feeds"]["status"]),
        "self_scan_decision": html.escape(self_scan["decision"]),
        "self_scan_findings": self_scan["finding_count"],
        "benchmark": "PASS" if benchmark["passed"] else "FAIL",
    }
    ranking_rows = []
    for row in status.get("vulnerability_ranking", []):
        ranking_rows.append(
            "<tr>"
            f"<td>{html.escape(row['repository'])}</td>"
            f"<td><code>{html.escape(row['target_sha'][:12])}</code></td>"
            f"<td>{html.escape(row['scan_status'])}</td>"
            f"<td>{row['critical']}</td><td>{row['high']}</td><td>{row['medium']}</td>"
            f"<td>{row['low']}</td><td>{row['unknown']}</td><td>{row['total']}</td>"
            "</tr>"
        )
    ranking_html = "" if not ranking_rows else """<h2>Vulnerability ranking</h2><p>Numeric aggregate only; locations and raw evidence are not published.</p><table><thead><tr><th>Repository</th><th>SHA</th><th>Status</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Unknown</th><th>Total</th></tr></thead><tbody>{}</tbody></table>""".format("".join(ranking_rows))
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>Observatory status</title>
<style>body{{font:16px system-ui,sans-serif;max-width:960px;margin:3rem auto;padding:0 1rem;color:#17202a}}main{{border:1px solid #d7dde3;border-radius:12px;padding:1.5rem}}dt{{font-weight:700;margin-top:.8rem}}dd{{margin:.15rem 0 0}}code{{font-size:.85em;overflow-wrap:anywhere}}table{{border-collapse:collapse;width:100%;margin-top:1rem}}th,td{{border:1px solid #d7dde3;padding:.45rem;text-align:right}}th:first-child,td:first-child{{text-align:left}}</style></head>
<body><main><h1>Observatory status</h1><dl>
<dt>Generated</dt><dd>{generated_at}</dd><dt>Last build</dt><dd><code>{build_sha}</code></dd><dt>Last publication</dt><dd>{last_publication}</dd><dt>Publication scope</dt><dd>{publication_scope}</dd>
<dt>Reports</dt><dd>{reports}</dd><dt>Digests</dt><dd>{digests}</dd><dt>Retractions</dt><dd>{retractions}</dd><dt>Partial scans</dt><dd>{partial_scans}</dd>
<dt>Feeds</dt><dd>{feed_status}</dd><dt>Self-scan</dt><dd>{self_scan_decision} ({self_scan_findings} findings)</dd><dt>Benchmark</dt><dd>{benchmark}</dd>
</dl>{ranking_html}</main></body></html>
""".format(ranking_html=ranking_html, **values)


def write_status_page(output_dir: Path, status):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    status_path = output_dir / "status.json"
    html_path = output_dir / "index.html"
    status_path.write_text(json.dumps(status, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    html_path.write_text(render_status_html(status), encoding="utf-8")
    return str(status_path), str(html_path)
