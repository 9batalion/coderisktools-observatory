"""Deterministic, local benchmark runner for scanner/policy contracts."""

from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import re
import tempfile

from observatory.normalization.findings import NormalizationError, normalize_scanner_findings
from observatory.policy.engine import evaluate_publication

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CASE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_MAX_MANIFEST_BYTES = 1024 * 1024
_MAX_CASES = 100
_MAX_FILES = 100
_MAX_FILE_BYTES = 1024 * 1024


class BenchmarkError(ValueError):
    """Raised when the benchmark manifest or result is unsafe/invalid."""


def _safe_path(value):
    if not isinstance(value, str) or not value or "\\" in value or value.startswith("/"):
        raise BenchmarkError("benchmark file path is unsafe")
    path = PurePosixPath(value)
    if ".." in path.parts or str(path) in {"", "."}:
        raise BenchmarkError("benchmark file path escapes fixture")
    return path


def _load_json(path):
    if path.stat().st_size > _MAX_MANIFEST_BYTES:
        raise BenchmarkError("benchmark manifest is too large")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise BenchmarkError("benchmark manifest is invalid JSON") from exc


def load_manifest(path):
    data = _load_json(Path(path))
    if not isinstance(data, dict) or set(data) != {"schema_version", "benchmark_version", "cases"}:
        raise BenchmarkError("benchmark manifest fields are invalid")
    if data["schema_version"] != 1 or not isinstance(data["benchmark_version"], str) or not data["benchmark_version"]:
        raise BenchmarkError("benchmark manifest version is invalid")
    cases = data["cases"]
    if not isinstance(cases, list) or not cases or len(cases) > _MAX_CASES:
        raise BenchmarkError("benchmark cases are invalid")
    seen = set()
    for case in cases:
        if not isinstance(case, dict) or set(case) != {"id", "files", "expected"}:
            raise BenchmarkError("benchmark case fields are invalid")
        case_id = case["id"]
        if not isinstance(case_id, str) or not _CASE_ID_RE.fullmatch(case_id) or case_id in seen:
            raise BenchmarkError("benchmark case id is invalid or duplicated")
        seen.add(case_id)
        files = case["files"]
        if not isinstance(files, list) or len(files) > _MAX_FILES:
            raise BenchmarkError("benchmark case files are invalid")
        file_paths = set()
        for item in files:
            if not isinstance(item, dict) or "path" not in item or set(item) - {"path", "content", "content_parts"}:
                raise BenchmarkError("benchmark fixture fields are invalid")
            has_content = "content" in item and "content_parts" not in item
            has_parts = "content_parts" in item and "content" not in item
            if not (has_content or has_parts):
                raise BenchmarkError("benchmark fixture content is invalid")
            path_value = _safe_path(item["path"])
            content = item["content"] if has_content else item["content_parts"]
            if has_parts and (not isinstance(content, list) or not content or not all(isinstance(part, str) for part in content)):
                raise BenchmarkError("benchmark fixture content parts are invalid")
            if isinstance(content, list):
                content = "".join(content)
            if str(path_value) in file_paths or not isinstance(content, str):
                raise BenchmarkError("benchmark fixture is invalid or duplicated")
            if len(content.encode("utf-8")) > _MAX_FILE_BYTES:
                raise BenchmarkError("benchmark fixture is too large")
            file_paths.add(str(path_value))
        expected = case["expected"]
        if not isinstance(expected, dict) or set(expected) != {"scan_status", "finding_count", "decision"}:
            raise BenchmarkError("benchmark expected result fields are invalid")
        if expected["scan_status"] not in {"complete", "partial", "failed"}:
            raise BenchmarkError("benchmark expected scan status is invalid")
        if not isinstance(expected["finding_count"], int) or expected["finding_count"] < 0:
            raise BenchmarkError("benchmark expected finding count is invalid")
        if expected["decision"] not in {"PUBLISH", "HOLD", "REDACT", "REJECT"}:
            raise BenchmarkError("benchmark expected decision is invalid")
    return data


def _materialize(case, root):
    for item in case["files"]:
        path = root / _safe_path(item["path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        content = item.get("content", "".join(item.get("content_parts", [])))
        path.write_text(content, encoding="utf-8")


def run_benchmark(manifest_path, adapter, ruleset_digest, license_status="recognized"):
    """Run all manifest cases and return deterministic machine-readable summaries."""
    if not isinstance(ruleset_digest, str) or not _DIGEST_RE.fullmatch(ruleset_digest):
        raise BenchmarkError("benchmark ruleset digest is invalid")
    if license_status not in {"recognized", "unknown", "restricted"}:
        raise BenchmarkError("benchmark license status is invalid")
    manifest = load_manifest(manifest_path)
    results = []
    for case in manifest["cases"]:
        target_sha = sha256(("observatory-benchmark:" + case["id"]).encode("utf-8")).hexdigest()[:40]
        with tempfile.TemporaryDirectory(prefix="observatory-benchmark-") as directory:
            root = Path(directory)
            _materialize(case, root)
            scan = adapter.scan(root, target_sha)
            if scan.ruleset_digest != ruleset_digest:
                raise BenchmarkError("benchmark scanner ruleset digest mismatch")
            errors = list(scan.errors)
            findings = []
            if scan.status == "complete" and not errors:
                try:
                    findings = normalize_scanner_findings(scan.findings, target_sha, scan.scanner_id)
                except NormalizationError as exc:
                    errors.append(f"normalization_failed:{exc}")
                    scan = type(scan)(scan.scanner_id, scan.scanner_version, scan.ruleset_digest, scan.target_sha, "failed", [], errors, list(scan.warnings))
            decision = evaluate_publication(scan.status, license_status, findings, errors)
        expected = case["expected"]
        actual = {"scan_status": scan.status, "finding_count": len(findings), "decision": decision.decision}
        passed = actual == expected
        results.append({
            "case_id": case["id"], "passed": passed,
            **actual, "expected": expected,
            "errors": list(scan.errors), "reason_codes": list(decision.reason_codes),
        })
    return results
