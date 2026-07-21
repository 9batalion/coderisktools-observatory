"""Local end-to-end scan runner."""

from dataclasses import dataclass
from pathlib import Path
import shutil

from observatory.acquisition.clone import acquire_repository
from observatory.contracts import Target
from observatory.normalization.findings import NormalizationError, normalize_scanner_findings
from observatory.policy.engine import evaluate_publication
from observatory.reporting.builder import ReportModel, build_report_bundle


@dataclass(frozen=True)
class PipelineResult:
    target: Target
    scan: object
    findings: list
    decision: object
    artifacts: list[Path]


def run_pipeline(source, resolved_sha, workspace, output_dir, repository_url, license_status, adapter, reviewer="operator"):
    """Run acquisition, scan, normalization, policy and report generation locally."""
    acquired = acquire_repository(str(source), resolved_sha, Path(workspace))
    try:
        scan = adapter.scan(acquired.path, resolved_sha)
        errors = list(scan.errors)
        findings = []
        if scan.status == "complete" and not errors:
            try:
                findings = normalize_scanner_findings(scan.findings, resolved_sha, scan.scanner_id)
            except NormalizationError as exc:
                errors.append(f"normalization_failed:{exc}")
                scan = type(scan)(scan.scanner_id, scan.scanner_version, scan.ruleset_digest, scan.target_sha, "failed", [], errors, list(scan.warnings))
        decision = evaluate_publication(scan.status, license_status, findings, errors)
        decision = type(decision).from_dict({**decision.__dict__, "reviewer": reviewer})
        target = Target.from_dict({
            "target_id": repository_url.rstrip("/").rsplit("/", 1)[-1],
            "repository_url": repository_url,
            "requested_ref": resolved_sha,
            "resolved_sha": resolved_sha,
            "source": "operator",
            "selection_reason": "explicit exact SHA local runner request",
            "license_status": license_status,
            "execution_allowed": False,
            "publication_mode": "public-summary",
            "status": "scanned",
        })
        model = ReportModel(target, scan, findings, decision, [
            "The runner does not execute analyzed repository code.",
            "A clean result is evidence, not certification.",
        ])
        artifacts = build_report_bundle(model, Path(output_dir), target.target_id)
        return PipelineResult(target, scan, findings, decision, artifacts)
    finally:
        shutil.rmtree(acquired.path, ignore_errors=True)
