"""Safe, offline-testable GitHub ref resolution."""

import re
from urllib.parse import urlsplit

from observatory.contracts import ContractError, Target

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_GITHUB_RE = re.compile(r"^https://github\.com/[^/]+/[^/]+/?$")


class ResolutionError(ValueError):
    """Raised when a target cannot be safely resolved to an exact SHA."""


def resolve_github_target(repository_url, requested_ref, resolver):
    """Resolve a GitHub ref using an injected resolver, never executing target code.

    The resolver is deliberately injected so offline callers can provide a local
    Git-backed resolver and tests do not need network access.
    """
    if not isinstance(repository_url, str) or not _GITHUB_RE.fullmatch(repository_url):
        raise ResolutionError("repository URL must be canonical GitHub HTTPS")
    parsed = urlsplit(repository_url)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ResolutionError("repository URL must not contain credentials or query data")
    if not isinstance(requested_ref, str) or not requested_ref or "\x00" in requested_ref:
        raise ResolutionError("requested ref must be a safe non-empty string")
    try:
        resolved = resolver(repository_url, requested_ref)
    except Exception as exc:
        raise ResolutionError("ref resolution failed") from exc
    if not isinstance(resolved, str) or not _SHA_RE.fullmatch(resolved):
        raise ResolutionError("resolver must return a full lowercase commit SHA")
    canonical_url = repository_url.rstrip("/")
    try:
        return Target.from_dict({
            "target_id": canonical_url.removeprefix("https://github.com/").replace("/", "-"),
            "repository_url": canonical_url,
            "requested_ref": requested_ref,
            "resolved_sha": resolved,
            "source": "operator",
            "selection_reason": "explicit target resolution",
            "license_status": "unknown",
            "execution_allowed": False,
            "publication_mode": "public-summary",
            "status": "candidate",
        })
    except ContractError as exc:
        raise ResolutionError(str(exc)) from exc
