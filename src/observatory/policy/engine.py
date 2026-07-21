"""Fail-closed publication policy evaluation."""

from observatory.contracts import NormalizedFinding, PublicationDecision


class PolicyError(ValueError):
    """Raised when policy inputs are invalid."""


def evaluate_publication(scan_status, license_status, findings, errors):
    if scan_status not in {"complete", "partial", "failed"}:
        raise PolicyError("invalid scan status")
    if license_status not in {"recognized", "unknown", "restricted"}:
        raise PolicyError("invalid license status")
    if not isinstance(findings, list) or not all(isinstance(item, NormalizedFinding) for item in findings):
        raise PolicyError("findings must contain NormalizedFinding values")
    if not isinstance(errors, list):
        raise PolicyError("errors must be a list")

    reasons = []
    decision = "PUBLISH"
    if scan_status != "complete":
        decision = "HOLD"
        reasons.append("SCAN_NOT_COMPLETE")
    if errors:
        decision = "HOLD"
        reasons.append("SCAN_ERRORS_PRESENT")
    if license_status != "recognized":
        decision = "HOLD"
        reasons.append("LICENSE_UNRESOLVED")

    for finding in findings:
        if finding.category == "secret-exposure":
            if finding.confidence == "low":
                decision = "REJECT"
                reasons.append("LOW_CONFIDENCE_SECRET")
            elif finding.confidence in {"high", "confirmed"}:
                decision = "HOLD"
                reasons.append("ACTIVE_SECRET_REQUIRES_REVIEW")
        elif finding.visibility == "EMBARGOED":
            decision = "HOLD"
            reasons.append("EMBARGO_REQUIRED")
        elif finding.visibility == "REDACTED":
            if decision == "PUBLISH":
                decision = "REDACT"
            reasons.append("REDACTION_REQUIRED")
        elif finding.visibility == "MAINTAINER_ONLY":
            decision = "HOLD"
            reasons.append("MAINTAINER_REVIEW_REQUIRED")

    if not reasons:
        reasons.append("COMPLETE_SCAN_NO_FINDINGS")
    # Preserve deterministic reason order while removing duplicates.
    reasons = list(dict.fromkeys(reasons))
    return PublicationDecision.from_dict({
        "decision": decision,
        "reviewer": "policy-engine",
        "reason_codes": reasons,
        "approved_artifacts": ["report.json", "report.md", "index.html", "manifest.json", "checksums.txt"],
        "full_findings_public": False,
        "override": False,
    })
