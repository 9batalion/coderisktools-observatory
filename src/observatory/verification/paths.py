"""Allowlist validation for publication pull requests."""

from pathlib import PurePosixPath

_ALLOWED_PREFIXES = ("public/", "operator/", "governance/")


def validate_publication_paths(paths):
    """Return paths that are unsafe or outside the publication allowlist."""
    rejected = []
    for raw in paths:
        path = str(raw)
        if not path or "\\" in path or path.startswith("/"):
            rejected.append(path)
            continue
        parts = PurePosixPath(path).parts
        if ".." in parts or not path.startswith(_ALLOWED_PREFIXES):
            rejected.append(path)
    return rejected
