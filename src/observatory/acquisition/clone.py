"""Bounded, no-exec repository acquisition."""

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


class AcquisitionError(RuntimeError):
    """Raised when acquisition cannot complete safely."""


@dataclass(frozen=True)
class AcquisitionLimits:
    timeout_seconds: int = 60
    max_files: int = 10000
    max_file_bytes: int = 10 * 1024 * 1024
    max_total_bytes: int = 100 * 1024 * 1024


@dataclass(frozen=True)
class AcquisitionResult:
    path: Path
    resolved_sha: str
    file_count: int
    total_bytes: int


def _run_git(args, timeout):
    env = os.environ.copy()
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"})
    try:
        return subprocess.run(
            ["git", *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            env=env,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AcquisitionError("git acquisition command failed") from exc


def _audit_tree(root: Path, limits: AcquisitionLimits):
    count = 0
    total = 0
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        dirs[:] = [name for name in dirs if name != ".git"]
        for name in dirs + files:
            path = Path(current) / name
            if path.is_symlink():
                raise AcquisitionError("symlinks are not allowed in the acquired working tree")
        for name in files:
            path = Path(current) / name
            size = path.stat().st_size
            count += 1
            total += size
            if count > limits.max_files:
                raise AcquisitionError("file count limit exceeded")
            if size > limits.max_file_bytes:
                raise AcquisitionError("single file size limit exceeded")
            if total > limits.max_total_bytes:
                raise AcquisitionError("total file size limit exceeded")
    return count, total


def acquire_repository(source: str, resolved_sha: str, workspace: Path, limits: AcquisitionLimits | None = None):
    """Clone a source at an exact SHA without hooks, submodules or code execution."""
    limits = limits or AcquisitionLimits()
    if not isinstance(resolved_sha, str) or len(resolved_sha) != 40 or any(c not in "0123456789abcdef" for c in resolved_sha):
        raise AcquisitionError("resolved_sha must be a full lowercase SHA")
    workspace = Path(workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    destination = Path(tempfile.mkdtemp(prefix="observatory-acquire-", dir=workspace))
    try:
        _run_git(["clone", "--no-checkout", "--no-recurse-submodules", "--depth", "1", str(source), str(destination)], limits.timeout_seconds)
        _run_git(["-C", str(destination), "config", "core.hooksPath", "/dev/null"], limits.timeout_seconds)
        _run_git(["-C", str(destination), "-c", "submodule.recurse=false", "checkout", "--detach", resolved_sha], limits.timeout_seconds)
        actual = _run_git(["-C", str(destination), "rev-parse", "HEAD"], limits.timeout_seconds).stdout.strip()
        if actual != resolved_sha:
            raise AcquisitionError("checked out SHA does not match requested SHA")
        count, total = _audit_tree(destination, limits)
        return AcquisitionResult(destination, actual, count, total)
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise
