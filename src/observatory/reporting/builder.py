"""Deterministic report package builder."""

from dataclasses import asdict, dataclass
import hashlib
import html
import json
from pathlib import Path

from observatory.contracts import NormalizedFinding, PublicationDecision, ScanResult, Target


@dataclass(frozen=True)
class ReportModel:
    target: Target
    scan: ScanResult
    findings: list[NormalizedFinding]
    decision: PublicationDecision
    limitations: list[str]


def _json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _write(path, data):
    path.write_bytes(data)
    return path


def _finding_dict(finding):
    return asdict(finding)


def _model_dict(model, repository_name):
    return {
        "schema_version": "1",
        "repository_name": repository_name,
        "repository_url": model.target.repository_url,
        "target": asdict(model.target),
        "scan": {
            "scanner_id": model.scan.scanner_id,
            "scanner_version": model.scan.scanner_version,
            "ruleset_digest": model.scan.ruleset_digest,
            "target_sha": model.scan.target_sha,
            "status": model.scan.status,
            "errors": list(model.scan.errors),
            "warnings": list(model.scan.warnings),
        },
        "findings": [_finding_dict(item) for item in model.findings],
        "publication_decision": asdict(model.decision),
        "limitations": list(model.limitations),
        "disclaimer": "Evidence, not certification. A clean result does not establish that the repository is secure.",
    }


def build_report_bundle(model: ReportModel, output_dir: Path, repository_name: str):
    """Write the core report bundle and return its deterministic artifact paths."""
    if not isinstance(model, ReportModel):
        raise TypeError("model must be ReportModel")
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    data = _model_dict(model, repository_name)
    report_json = _write(output_dir / "report.json", _json_bytes(data))
    summary = {
        "target_sha": model.target.resolved_sha,
        "status": model.scan.status,
        "finding_count": len(model.findings),
        "error_count": len(model.scan.errors),
        "warning_count": len(model.scan.warnings),
    }
    summary_path = _write(output_dir / "scan-summary.json", _json_bytes(summary))
    decision_path = _write(output_dir / "publication-decision.json", _json_bytes(asdict(model.decision)))
    review_path = _write(output_dir / "review-record.json", _json_bytes({
        "reviewer": model.decision.reviewer,
        "decision": model.decision.decision,
        "reason_codes": model.decision.reason_codes,
        "target_sha": model.target.resolved_sha,
        "manual_gate_required": True,
    }))
    markdown = "\n".join([
        f"# Observatory report: {repository_name}", "",
        f"- Repository: {model.target.repository_url}",
        f"- Exact commit SHA: `{model.target.resolved_sha}`",
        f"- Scan status: **{model.scan.status}**",
        f"- Scanner: `{model.scan.scanner_id}` {model.scan.scanner_version}",
        f"- Publication proposal: **{model.decision.decision}**",
        "",
        "## Evidence, not certification", "",
        "A clean result does not establish that the repository is secure.", "",
        "## Limitations", "",
        *[f"- {item}" for item in model.limitations], "",
    ]).encode("utf-8")
    markdown_path = _write(output_dir / "report.md", markdown)
    safe_name = html.escape(str(repository_name), quote=True)
    html_body = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Observatory report</title></head><body>"
    html_body += f"<h1>Observatory report: {safe_name}</h1><p>Exact commit SHA: <code>{html.escape(model.target.resolved_sha)}</code></p>"
    html_body += f"<p>Status: <strong>{html.escape(model.scan.status)}</strong></p><p>Evidence, not certification.</p></body></html>\n"
    html_path = _write(output_dir / "index.html", html_body.encode("utf-8"))

    members = [report_json, markdown_path, html_path, summary_path, decision_path, review_path]
    manifest = {
        "manifest_version": "1",
        "target_sha": model.target.resolved_sha,
        "artifacts": [{"name": path.name, "size": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for path in sorted(members, key=lambda p: p.name)],
    }
    manifest_path = _write(output_dir / "manifest.json", _json_bytes(manifest))
    checksum_members = members + [manifest_path]
    checksums = "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in sorted(checksum_members, key=lambda p: p.name))
    checksums_path = _write(output_dir / "checksums.txt", checksums.encode("ascii"))
    return [*sorted(checksum_members, key=lambda p: p.name), checksums_path]
