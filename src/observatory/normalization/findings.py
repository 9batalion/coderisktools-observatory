"""Deterministic, secret-safe finding normalization."""

from hashlib import sha256
from pathlib import PurePosixPath
import re

from observatory.contracts import NormalizedFinding

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class NormalizationError(ValueError):
    """Raised when external finding data cannot be safely normalized."""


def _safe_path(value):
    if not isinstance(value, str) or not value or "\\" in value or value.startswith("/"):
        raise NormalizationError("finding path is unsafe")
    parts = PurePosixPath(value).parts
    if ".." in parts:
        raise NormalizationError("finding path escapes target")
    return str(PurePosixPath(value))


def normalize_scanner_findings(raw_findings, target_sha, scanner_id):
    if not isinstance(target_sha, str) or not _SHA_RE.fullmatch(target_sha):
        raise NormalizationError("target SHA must be full lowercase SHA")
    if not isinstance(raw_findings, list):
        raise NormalizationError("findings must be a list")
    normalized = []
    for raw in raw_findings:
        if not isinstance(raw, dict):
            raise NormalizationError("finding must be an object")
        if raw.get("matched_text") != "[REDACTED]" or raw.get("line_content") != "[REDACTED]":
            raise NormalizationError("finding evidence must already be redacted")
        fingerprint = raw.get("fingerprint")
        if not isinstance(fingerprint, str) or not _DIGEST_RE.fullmatch(fingerprint):
            raise NormalizationError("finding requires a safe fingerprint evidence reference")
        path = _safe_path(raw.get("file"))
        rule_id = raw.get("rule_id")
        severity = raw.get("severity")
        confidence = raw.get("confidence")
        if not isinstance(rule_id, str) or not rule_id:
            raise NormalizationError("finding rule_id is required")
        if severity not in {"informational", "low", "medium", "high", "critical"}:
            raise NormalizationError("invalid finding severity")
        if confidence not in {"low", "medium", "high", "confirmed"}:
            raise NormalizationError("invalid finding confidence")
        category = "secret-exposure" if raw.get("category") == "secret" or raw.get("type") == "secret" else "unknown"
        identity = "\0".join((scanner_id, target_sha, rule_id, path, fingerprint))
        finding_id = "finding-sha256:" + sha256(identity.encode("utf-8")).hexdigest()
        remediation = raw.get("remediation")
        if not isinstance(remediation, str) or not remediation.strip() or "\x00" in remediation:
            remediation = "Review the finding and rotate/remove sensitive material as appropriate."
        normalized.append(NormalizedFinding.from_dict({
            "finding_id": finding_id,
            "rule_id": rule_id,
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "visibility": "MAINTAINER_ONLY" if category == "secret-exposure" else "PUBLIC_SUMMARY",
            "evidence_refs": [fingerprint],
            "location": {"path": path, "commit": target_sha},
            "summary": "Potential credential material detected" if category == "secret-exposure" else "Repository risk pattern detected",
            "remediation": remediation,
            "source_scanners": [scanner_id],
        }))
    return normalized
