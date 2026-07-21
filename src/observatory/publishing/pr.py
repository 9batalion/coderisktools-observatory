"""Safe local staging for report-repository pull requests."""

from dataclasses import dataclass
import json
from pathlib import Path
import shutil
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
