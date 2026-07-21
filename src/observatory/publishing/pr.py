"""Safe local staging and PR creation for report-repository submissions."""

from dataclasses import dataclass
import json
from pathlib import Path
import shutil
import subprocess
from urllib.parse import urlsplit

from observatory.verification.bundle import verify_bundle


class PublicationError(ValueError):
    """Raised when a bundle cannot pass the publication gate."""


@dataclass(frozen=True)
class PublicationPlan:
    destination: Path
    artifacts: list[Path]
    target_sha: str
    repository_url: str
    revision: int


@dataclass(frozen=True)
class PullRequestResult:
    url: str
    branch: str
    commit: str
    plan: PublicationPlan


_ARTIFACTS = (
    "report.json", "report.md", "index.html", "scan-summary.json",
    "publication-decision.json", "review-record.json", "manifest.json", "checksums.txt",
)


def _safe_slug(value):
    if not value or value in {".", ".."} or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_." for char in value):
        raise PublicationError("unsafe repository path component")
    return value


def prepare_publication(reports_repo, bundle, revision=1):
    reports_repo = Path(reports_repo)
    bundle = Path(bundle)
    if not isinstance(revision, int) or revision < 1:
        raise PublicationError("revision must be a positive integer")
    if reports_repo.is_symlink() or bundle.is_symlink() or not bundle.is_dir():
        raise PublicationError("repository and bundle paths must be real directories")
    verification = verify_bundle(bundle)
    if not verification.valid:
        raise PublicationError("bundle verification failed")
    try:
        report = json.loads((bundle / "report.json").read_text(encoding="utf-8"))
        decision = json.loads((bundle / "publication-decision.json").read_text(encoding="utf-8"))
        repository_url = report["repository_url"]
        target_sha = report["target"]["resolved_sha"]
        if decision["decision"] != "PUBLISH":
            raise PublicationError("only PUBLISH decisions may be staged")
    except PublicationError:
        raise
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise PublicationError("publication metadata is invalid") from exc
    parsed = urlsplit(repository_url)
    if parsed.scheme != "https" or parsed.netloc != "github.com" or parsed.path.count("/") != 2:
        raise PublicationError("repository URL is not canonical GitHub HTTPS")
    owner, repo = parsed.path.strip("/").split("/")
    owner = _safe_slug(owner)
    repo = _safe_slug(repo)
    _safe_slug(target_sha)
    destination = reports_repo / "public" / "reports" / "github" / owner / repo / target_sha / f"r{revision}"
    if destination.exists() or destination.is_symlink():
        raise PublicationError("publication revision already exists")
    missing = [name for name in _ARTIFACTS if not (bundle / name).is_file() or (bundle / name).is_symlink()]
    if missing:
        raise PublicationError("bundle is missing required artifacts")
    reports_repo.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    if temporary.exists():
        shutil.rmtree(temporary)
    temporary.mkdir(parents=True)
    try:
        for name in _ARTIFACTS:
            shutil.copy2(bundle / name, temporary / name)
        temporary.replace(destination)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return PublicationPlan(destination, [destination / name for name in _ARTIFACTS], target_sha, repository_url, revision)


def _run_git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout.strip()


def create_publication_pr(reports_repo, bundle, revision=1, branch=None, title=None, body=None, remote_repo=None):
    """Create a branch, commit the verified public bundle, push it, and open a GitHub PR."""
    repo = Path(reports_repo)
    if not repo.is_dir() or repo.is_symlink():
        raise PublicationError("reports repository must be a real checkout")
    if _run_git(repo, "status", "--porcelain"):
        raise PublicationError("reports repository worktree must be clean")
    _run_git(repo, "fetch", "origin", "main")
    if branch is None:
        branch = f"publish/observatory-{revision}"
    _safe_slug(branch.replace("/", "-"))
    _run_git(repo, "switch", "-c", branch, "origin/main")
    plan = prepare_publication(repo, bundle, revision)
    relative_files = [str(path.relative_to(repo)) for path in plan.artifacts]
    _run_git(repo, "add", "--", *relative_files)
    commit_message = title or f"feat: publish Observatory report {plan.target_sha[:12]}"
    _run_git(repo, "commit", "-m", commit_message)
    commit = _run_git(repo, "rev-parse", "HEAD")
    _run_git(repo, "push", "-u", "origin", branch)
    if remote_repo is None:
        remote = _run_git(repo, "remote", "get-url", "origin")
        remote = remote.removesuffix(".git")
        if remote.startswith("git@github.com:"):
            remote_repo = remote.removeprefix("git@github.com:")
        else:
            remote_repo = urlsplit(remote).path.strip("/")
    pr_body = body or (
        "## Summary\n- Publishes a verified Observatory report bundle.\n"
        f"- Exact target SHA: `{plan.target_sha}`\n"
        "- Publication is evidence, not certification.\n\n"
        "## Gate\n- Local bundle verifier passed.\n- Publication decision is `PUBLISH`.\n"
    )
    result = subprocess.run(
        ["gh", "pr", "create", "--repo", remote_repo, "--base", "main", "--head", branch, "--title", commit_message, "--body", pr_body],
        cwd=repo, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    url = result.stdout.strip().splitlines()[-1]
    if not url.startswith("https://github.com/"):
        raise PublicationError("gh did not return a canonical PR URL")
    return PullRequestResult(url, branch, commit, plan)
