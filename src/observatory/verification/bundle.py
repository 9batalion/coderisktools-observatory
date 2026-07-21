"""Fail-closed verification of a published report bundle."""

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

from observatory.verification.schema import SchemaValidationError, validate_json_file

_REQUIRED = {
    "report.json", "report.md", "index.html", "scan-summary.json",
    "publication-decision.json", "review-record.json",
}
_SCHEMA_ROOT = Path(__file__).resolve().parents[3] / "schemas"
_SCHEMA_FILES = {
    "manifest.json": "manifest.schema.json",
    "report.json": "report.schema.json",
    "publication-decision.json": "publication-decision.schema.json",
    "review-record.json": "review-record.schema.json",
    "scan-summary.json": "scan-summary.schema.json",
}


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    errors: list[str]
    checked_files: list[str]


def _safe_name(value):
    if not isinstance(value, str) or not value or value.startswith("/") or "\\" in value:
        return False
    path = PurePosixPath(value)
    return path.as_posix() == value and ".." not in path.parts and len(path.parts) == 1


def _digest(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_bundle(root):
    root = Path(root)
    errors = []
    checked = []
    if not root.is_dir() or root.is_symlink():
        return VerificationResult(False, ["bundle root is not a directory"], [])
    for current, dirs, files in __import__("os").walk(root, followlinks=False):
        for name in dirs + files:
            if (Path(current) / name).is_symlink():
                errors.append(f"symlink rejected: {Path(current, name).relative_to(root)}")
    manifest_path = root / "manifest.json"
    checksums_path = root / "checksums.txt"
    if not manifest_path.is_file():
        errors.append("missing manifest.json")
    if not checksums_path.is_file():
        errors.append("missing checksums.txt")
    if errors:
        return VerificationResult(False, errors, checked)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return VerificationResult(False, [f"invalid manifest: {exc}"], checked)
    for artifact_name, schema_name in _SCHEMA_FILES.items():
        artifact_path = root / artifact_name
        schema_path = _SCHEMA_ROOT / schema_name
        try:
            validate_json_file(artifact_path, schema_path)
        except (OSError, SchemaValidationError) as exc:
            errors.append(f"schema validation failed: {artifact_name}: {exc}")
    documents = {"manifest.json": manifest}
    for artifact_name in ("report.json", "scan-summary.json", "publication-decision.json", "review-record.json"):
        try:
            documents[artifact_name] = json.loads((root / artifact_name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            documents[artifact_name] = None
    report = documents.get("report.json") if isinstance(documents.get("report.json"), dict) else {}
    summary = documents.get("scan-summary.json") if isinstance(documents.get("scan-summary.json"), dict) else {}
    decision = documents.get("publication-decision.json") if isinstance(documents.get("publication-decision.json"), dict) else {}
    review = documents.get("review-record.json") if isinstance(documents.get("review-record.json"), dict) else {}
    if all(isinstance(item, dict) for item in (manifest, report, summary, decision, review)):
        sha_values = {
            "manifest": manifest.get("target_sha"),
            "report.target": report.get("target", {}).get("resolved_sha"),
            "report.scan": report.get("scan", {}).get("target_sha"),
            "summary": summary.get("target_sha"),
            "review": review.get("target_sha"),
        }
        if len(set(sha_values.values())) != 1:
            errors.append("cross-artifact target_sha mismatch: " + json.dumps(sha_values, sort_keys=True))
        if report.get("repository_url") != report.get("target", {}).get("repository_url"):
            errors.append("cross-artifact repository_url mismatch")
        decisions = {
            "report": report.get("publication_decision", {}).get("decision"),
            "publication-decision": decision.get("decision"),
            "review": review.get("decision"),
        }
        if len(set(decisions.values())) != 1:
            errors.append("cross-artifact decision mismatch: " + json.dumps(decisions, sort_keys=True))
        counts = {
            "finding_count": (summary.get("finding_count"), len(report.get("findings", []))),
            "error_count": (summary.get("error_count"), len(report.get("scan", {}).get("errors", []))),
            "warning_count": (summary.get("warning_count"), len(report.get("scan", {}).get("warnings", []))),
        }
        for name, (declared, actual) in counts.items():
            if declared != actual:
                errors.append(f"cross-artifact {name} mismatch: declared={declared} actual={actual}")
    artifacts = manifest.get("artifacts") if isinstance(manifest, dict) else None
    if not isinstance(artifacts, list):
        return VerificationResult(False, ["manifest artifacts must be a list"], checked)
    seen = set()
    for item in artifacts:
        if not isinstance(item, dict) or not _safe_name(item.get("name")):
            errors.append("unsafe manifest artifact name")
            continue
        name = item["name"]
        if name in seen:
            errors.append(f"duplicate manifest artifact: {name}")
            continue
        seen.add(name)
        path = root / name
        if not path.is_file() or path.is_symlink():
            errors.append(f"missing or unsafe artifact: {name}")
            continue
        expected = item.get("sha256")
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            errors.append(f"invalid hash metadata: {name}")
            continue
        declared_size = item.get("size")
        if not isinstance(declared_size, int) or isinstance(declared_size, bool) or declared_size != path.stat().st_size:
            errors.append(f"size mismatch: {name}")
            continue
        actual = _digest(path)
        checked.append(name)
        if actual != expected:
            errors.append(f"hash mismatch: {name}")
    if seen != _REQUIRED:
        errors.append("manifest artifact set does not match required report artifacts")

    checksum_names = set()
    try:
        lines = checksums_path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as exc:
        return VerificationResult(False, [f"invalid checksums.txt: {exc}"], checked)
    for line in lines:
        parts = line.split("  ", 1)
        if len(parts) != 2 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]) or not _safe_name(parts[1]):
            errors.append("invalid checksums entry")
            continue
        digest, name = parts
        if name in checksum_names:
            errors.append(f"duplicate checksum entry: {name}")
            continue
        checksum_names.add(name)
        path = root / name
        if not path.is_file() or path.is_symlink():
            errors.append(f"checksum file missing or unsafe: {name}")
            continue
        if _digest(path) != digest:
            errors.append(f"checksum mismatch: {name}")
    if checksum_names != (_REQUIRED | {"manifest.json"}):
        errors.append("checksum artifact set is incomplete or contains extras")
    return VerificationResult(not errors, errors, sorted(set(checked)))
