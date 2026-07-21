"""Immutability validation for the public report tree."""

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import stat


@dataclass(frozen=True)
class ImmutabilityResult:
    valid: bool
    errors: list[str]
    checked_paths: int


def _tree(root):
    files = {}
    report_root = root / "public" / "reports"
    if not report_root.exists():
        return files
    if report_root.is_symlink() or not report_root.is_dir():
        raise ValueError("invalid public/reports root")
    for path in report_root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"symlink report path: {relative}")
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError(f"non-regular report path: {relative}")
        files[relative] = path.read_bytes()
    return files


def _validate_path(value):
    parts = PurePosixPath(value).parts
    if value.startswith("/") or "\\" in value or not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"unsafe changed path: {value}")
    if len(parts) != 8 or parts[:3] != ("public", "reports", "github"):
        raise ValueError(f"path outside canonical report tree: {value}")
    owner, repo, target_sha, revision, filename = parts[3:]
    if not owner or not repo or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_." for c in owner + repo):
        raise ValueError(f"unsafe repository identity: {value}")
    if len(target_sha) != 40 or target_sha != target_sha.lower() or any(c not in "0123456789abcdef" for c in target_sha):
        raise ValueError(f"invalid target SHA: {value}")
    if not revision.startswith("r") or not revision[1:].isdigit() or int(revision[1:]) < 1:
        raise ValueError(f"invalid report revision: {value}")
    if filename == "retraction.json":
        return parts, True
    if filename not in {"report.json", "report.md", "index.html", "scan-summary.json", "publication-decision.json", "review-record.json", "manifest.json", "checksums.txt"}:
        raise ValueError(f"unexpected report artifact: {value}")
    return parts, False


def verify_immutability(base, candidate, changed_paths):
    base = Path(base); candidate = Path(candidate)
    errors = []
    try:
        if base.is_symlink() or candidate.is_symlink() or not base.is_dir() or not candidate.is_dir():
            raise ValueError("base and candidate must be real directories")
        values = list(changed_paths)
        if not values or len(values) != len(set(values)):
            raise ValueError("changed paths must be non-empty and unique")
        parsed = [_validate_path(value) for value in values]
        base_files = _tree(base)
        candidate_files = _tree(candidate)
        actual = {path for path in set(base_files) | set(candidate_files) if base_files.get(path) != candidate_files.get(path)}
        if actual != set(values):
            raise ValueError("changed-path list does not match the actual report-tree diff")
        new_revisions = set()
        for value, (parts, is_retraction) in zip(values, parsed):
            revision_root = "/".join(parts[:7])
            if value not in candidate_files:
                raise ValueError(f"report path was deleted: {value}")
            if revision_root in {path.rsplit("/", 1)[0] for path in base_files}:
                if not is_retraction or value in base_files:
                    raise ValueError(f"existing report is immutable: {value}")
            else:
                new_revisions.add(revision_root)
        if len(new_revisions) > 1:
            raise ValueError("one publication PR may add only one new report revision")
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        errors.append(str(exc))
    return ImmutabilityResult(not errors, errors, len(changed_paths))
