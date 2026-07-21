"""Fail-closed retraction records and PR creation."""

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
from urllib.parse import urlsplit

from observatory.publishing.pr import PublicationError, _run_git, _safe_slug
from observatory.verification.schema import SchemaValidationError, validate

_SCHEMA_PATH = Path(__file__).resolve().parents[3] / "schemas" / "retraction.schema.json"


@dataclass(frozen=True)
class RetractionPlan:
    path: Path
    repository_url: str
    target_sha: str
    revision: int
    retracted_at: str


@dataclass(frozen=True)
class RetractionPrResult:
    url: str
    branch: str
    commit: str
    plan: RetractionPlan


def _canonical_url(value):
    parsed = urlsplit(value.rstrip("/"))
    if parsed.scheme != "https" or parsed.netloc != "github.com" or parsed.path.count("/") != 2:
        raise PublicationError("repository URL is not canonical GitHub HTTPS")
    owner, repo = parsed.path.strip("/").split("/")
    return value.rstrip("/"), _safe_slug(owner), _safe_slug(repo)


def _timestamp(value):
    if value is None:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PublicationError("timestamp must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PublicationError("timestamp must include timezone")
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def prepare_retraction(reports_repo, repository_url, target_sha, revision=1, reason="", retracted_at=None):
    repo = Path(reports_repo)
    if repo.is_symlink() or not repo.is_dir():
        raise PublicationError("reports repository must be a real checkout")
    canonical_url, owner, name = _canonical_url(repository_url)
    if not isinstance(target_sha, str) or len(target_sha) != 40 or target_sha != target_sha.lower() or any(c not in "0123456789abcdef" for c in target_sha):
        raise PublicationError("target SHA must be a lowercase full SHA")
    if not isinstance(revision, int) or revision < 1:
        raise PublicationError("revision must be a positive integer")
    reason = reason.strip() if isinstance(reason, str) else ""
    if not reason or len(reason) > 2000 or any(ord(c) < 32 and c not in "\n\t" for c in reason):
        raise PublicationError("retraction reason is required and bounded")
    destination = repo / "public" / "reports" / "github" / owner / name / target_sha / f"r{revision}"
    report_path = destination / "report.json"
    path = destination / "retraction.json"
    if not destination.is_dir() or destination.is_symlink() or not report_path.is_file() or report_path.is_symlink():
        raise PublicationError("published report revision does not exist")
    if path.exists() or path.is_symlink():
        raise PublicationError("retraction already exists")
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if report["repository_url"] != canonical_url or report["target"]["resolved_sha"] != target_sha:
            raise PublicationError("published report identity does not match retraction request")
    except PublicationError:
        raise
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise PublicationError("published report metadata is invalid") from exc
    payload = {
        "head_commit": target_sha,
        "message": "This report has been withdrawn and is unavailable.",
        "reason": reason,
        "report_revision": revision,
        "repository": f"{owner}/{name}",
        "retracted_at": _timestamp(retracted_at),
        "schema_version": "1.0",
        "status": "WITHDRAWN",
    }
    try:
        schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
        validate(payload, schema)
    except (OSError, json.JSONDecodeError, SchemaValidationError) as exc:
        raise PublicationError("retraction payload failed schema validation") from exc
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    temporary.replace(path)
    return RetractionPlan(path, canonical_url, target_sha, revision, payload["retracted_at"])


def create_retraction_pr(reports_repo, repository_url, target_sha, revision=1, reason="", retracted_at=None, branch=None, title=None, body=None, remote_repo=None):
    repo = Path(reports_repo)
    if _run_git(repo, "status", "--porcelain"):
        raise PublicationError("reports repository worktree must be clean")
    _run_git(repo, "fetch", "origin", "main")
    branch = branch or f"retract/observatory-{target_sha[:12]}-r{revision}"
    _safe_slug(branch.replace("/", "-"))
    _run_git(repo, "switch", "-c", branch, "origin/main")
    plan = prepare_retraction(repo, repository_url, target_sha, revision, reason, retracted_at)
    relative = str(plan.path.relative_to(repo))
    _run_git(repo, "add", "--", relative)
    commit_message = title or f"docs: retract Observatory report {target_sha[:12]}"
    _run_git(repo, "commit", "-m", commit_message)
    commit = _run_git(repo, "rev-parse", "HEAD")
    _run_git(repo, "push", "-u", "origin", branch)
    if remote_repo is None:
        remote = _run_git(repo, "remote", "get-url", "origin").removesuffix(".git")
        remote_repo = remote.removeprefix("git@github.com:") if remote.startswith("git@github.com:") else urlsplit(remote).path.strip("/")
    pr_body = body or f"## Summary\n- Retracts report `{target_sha}` revision `{revision}`.\n- Reason: {reason}\n"
    result = subprocess.run(["gh", "pr", "create", "--repo", remote_repo, "--base", "main", "--head", branch, "--title", commit_message, "--body", pr_body], cwd=repo, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    url = result.stdout.strip().splitlines()[-1]
    if not url.startswith("https://github.com/"):
        raise PublicationError("gh did not return a canonical PR URL")
    return RetractionPrResult(url, branch, commit, plan)
