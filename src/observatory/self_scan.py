"""Fail-closed self-scan of the Observatory source tree."""

import re
import subprocess
from pathlib import Path

from observatory.normalization.findings import NormalizationError, normalize_scanner_findings
from observatory.policy.engine import evaluate_publication

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class SelfScanError(RuntimeError):
    """Raised when self-scan provenance or execution cannot be established."""


def _head(path):
    try:
        completed = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            check=True, shell=False, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SelfScanError("self-scan requires a readable Git HEAD") from exc
    value = completed.stdout.strip()
    if not _SHA_RE.fullmatch(value):
        raise SelfScanError("self-scan HEAD is not a full lowercase SHA")
    return value


def run_self_scan(path, adapter, ruleset_digest):
    """Scan the current repository tree and return a raw-evidence-free summary."""
    root = Path(path)
    if not root.is_dir():
        raise SelfScanError("self-scan path must be a directory")
    if not isinstance(ruleset_digest, str) or not _DIGEST_RE.fullmatch(ruleset_digest):
        raise SelfScanError("self-scan ruleset digest is invalid")
    target_sha = _head(root)
    scan = adapter.scan(root, target_sha)
    if scan.ruleset_digest != ruleset_digest:
        raise SelfScanError("self-scan scanner ruleset digest mismatch")
    errors = list(scan.errors)
    findings = []
    if scan.status == "complete" and not errors:
        try:
            findings = normalize_scanner_findings(scan.findings, target_sha, scan.scanner_id)
        except NormalizationError as exc:
            errors.append(f"normalization_failed:{exc}")
            scan = type(scan)(scan.scanner_id, scan.scanner_version, scan.ruleset_digest, scan.target_sha, "failed", [], errors, list(scan.warnings))
    decision = evaluate_publication(scan.status, "recognized", findings, errors)
    return {
        "target_sha": target_sha,
        "scanner_id": scan.scanner_id,
        "scanner_version": scan.scanner_version,
        "scan_status": scan.status,
        "finding_count": len(findings),
        "decision": decision.decision,
        "reason_codes": list(decision.reason_codes),
        "errors": errors,
        "warnings": list(scan.warnings),
    }
