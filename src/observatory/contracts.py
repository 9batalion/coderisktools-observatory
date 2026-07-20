"""Closed, dependency-free data contracts for the Observatory pipeline."""

from dataclasses import dataclass
import re
from typing import Any
from urllib.parse import urlsplit

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_GITHUB_RE = re.compile(r"^https://github\.com/[^/]+/[^/]+/?$")


class ContractError(ValueError):
    """Raised when an input violates a closed Observatory contract."""


def _mapping(data: Any) -> dict:
    if not isinstance(data, dict):
        raise ContractError("object required")
    return data


def _required(data: dict, keys: tuple[str, ...]) -> None:
    missing = [key for key in keys if key not in data]
    if missing:
        raise ContractError("missing required fields: " + ",".join(missing))


def _sha(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SHA_RE.fullmatch(value):
        raise ContractError(f"{field} must be a full lowercase commit SHA")
    return value


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ContractError(f"{field} must be a sha256 digest")
    return value


def _string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ContractError(f"{field} must be a non-empty safe string")
    return value


@dataclass(frozen=True)
class Target:
    target_id: str
    repository_url: str
    requested_ref: str
    resolved_sha: str
    source: str
    selection_reason: str
    license_status: str
    execution_allowed: bool
    publication_mode: str
    status: str

    @classmethod
    def from_dict(cls, raw: Any) -> "Target":
        data = _mapping(raw)
        fields = ("target_id", "repository_url", "requested_ref", "resolved_sha", "source", "selection_reason", "license_status", "execution_allowed", "publication_mode", "status")
        _required(data, fields)
        if set(data) != set(fields):
            raise ContractError("unknown Target field")
        url = data["repository_url"]
        parsed = urlsplit(url) if isinstance(url, str) else None
        if not isinstance(url, str) or not _GITHUB_RE.fullmatch(url) or parsed.username or parsed.password or "?" in url or "#" in url:
            raise ContractError("repository_url must be a credential-free canonical GitHub HTTPS URL")
        if not isinstance(data["execution_allowed"], bool) or data["execution_allowed"]:
            raise ContractError("execution_allowed must be false for the base pipeline")
        if data["license_status"] not in {"recognized", "unknown", "restricted"}:
            raise ContractError("invalid license_status")
        if data["publication_mode"] not in {"public-summary", "maintainer-only", "embargoed", "redacted"}:
            raise ContractError("invalid publication_mode")
        if data["status"] not in {"candidate", "triaged", "ready", "acquired", "scanned", "rejected"}:
            raise ContractError("invalid status")
        return cls(*( _string(data[k], k) if k not in {"resolved_sha", "execution_allowed"} else (_sha(data[k], k) if k == "resolved_sha" else data[k]) for k in fields))


@dataclass(frozen=True)
class ScanResult:
    scanner_id: str
    scanner_version: str
    ruleset_digest: str
    target_sha: str
    status: str
    findings: list
    errors: list
    warnings: list

    @classmethod
    def from_dict(cls, raw: Any) -> "ScanResult":
        data = _mapping(raw)
        fields = ("scanner_id", "scanner_version", "ruleset_digest", "target_sha", "status", "findings", "errors", "warnings")
        _required(data, fields)
        if set(data) != set(fields):
            raise ContractError("unknown ScanResult field")
        _digest(data["ruleset_digest"], "ruleset_digest")
        _sha(data["target_sha"], "target_sha")
        if data["status"] not in {"complete", "partial", "failed"}:
            raise ContractError("invalid scan status")
        for key in ("findings", "errors", "warnings"):
            if not isinstance(data[key], list):
                raise ContractError(f"{key} must be an array")
        return cls(_string(data["scanner_id"], "scanner_id"), _string(data["scanner_version"], "scanner_version"), data["ruleset_digest"], data["target_sha"], data["status"], list(data["findings"]), list(data["errors"]), list(data["warnings"]))


@dataclass(frozen=True)
class NormalizedFinding:
    finding_id: str
    rule_id: str
    category: str
    severity: str
    confidence: str
    visibility: str
    evidence_refs: list
    location: dict
    summary: str
    remediation: str
    source_scanners: list

    @classmethod
    def from_dict(cls, raw: Any) -> "NormalizedFinding":
        data = _mapping(raw)
        fields = ("finding_id", "rule_id", "category", "severity", "confidence", "visibility", "evidence_refs", "location", "summary", "remediation", "source_scanners")
        _required(data, fields)
        if set(data) != set(fields):
            raise ContractError("unknown NormalizedFinding field")
        if data["severity"] not in {"low", "medium", "high", "critical", "informational"}:
            raise ContractError("invalid severity")
        if data["confidence"] not in {"low", "medium", "high", "confirmed"}:
            raise ContractError("invalid confidence")
        if data["visibility"] not in {"PUBLIC_SUMMARY", "MAINTAINER_ONLY", "EMBARGOED", "REDACTED", "REJECTED"}:
            raise ContractError("invalid visibility")
        if not isinstance(data["evidence_refs"], list) or any(not _DIGEST_RE.fullmatch(str(x)) for x in data["evidence_refs"]):
            raise ContractError("evidence_refs must contain sha256 digests")
        if data["confidence"] == "confirmed" and not data["evidence_refs"]:
            raise ContractError("confirmed finding requires evidence")
        if not isinstance(data["location"], dict) or "commit" not in data["location"]:
            raise ContractError("location with commit is required")
        _sha(data["location"]["commit"], "location.commit")
        return cls(*[_string(data[k], k) if k not in {"evidence_refs", "location", "source_scanners"} else data[k] for k in fields])


@dataclass(frozen=True)
class PublicationDecision:
    decision: str
    reviewer: str
    reason_codes: list
    approved_artifacts: list
    full_findings_public: bool
    override: bool = False
    override_reason: str | None = None

    @classmethod
    def from_dict(cls, raw: Any) -> "PublicationDecision":
        data = _mapping(raw)
        required = ("decision", "reviewer", "reason_codes", "approved_artifacts", "full_findings_public")
        _required(data, required)
        allowed = set(required) | {"override", "override_reason"}
        if set(data) - allowed:
            raise ContractError("unknown PublicationDecision field")
        if data["decision"] not in {"PUBLISH", "HOLD", "REDACT", "REJECT"}:
            raise ContractError("invalid decision")
        if not isinstance(data["reason_codes"], list) or not data["reason_codes"]:
            raise ContractError("reason_codes are required")
        if not isinstance(data["approved_artifacts"], list):
            raise ContractError("approved_artifacts must be an array")
        if not isinstance(data["full_findings_public"], bool):
            raise ContractError("full_findings_public must be boolean")
        override = data.get("override", False)
        if not isinstance(override, bool):
            raise ContractError("override must be boolean")
        if override and not data.get("override_reason"):
            raise ContractError("override_reason is required for override")
        return cls(_string(data["decision"], "decision"), _string(data["reviewer"], "reviewer"), list(data["reason_codes"]), list(data["approved_artifacts"]), data["full_findings_public"], override, data.get("override_reason"))
