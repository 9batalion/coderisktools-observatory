import json
import io
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import unittest
from unittest import mock

from observatory.contracts import PublicationDecision, ScanResult, Target
from observatory.reporting.builder import ReportModel, build_report_bundle
from observatory.publishing.pr import PublicationError, _extract_archive, create_publication_pr, prepare_publication

SHA = "f" * 40
DIGEST = "sha256:" + "1" * 64


def make_bundle(root, decision_name="PUBLISH"):
    target = Target.from_dict({
        "target_id": "owner-repo", "repository_url": "https://github.com/owner/repo",
        "requested_ref": "main", "resolved_sha": SHA, "source": "operator",
        "selection_reason": "test", "license_status": "recognized",
        "execution_allowed": False, "publication_mode": "public-summary", "status": "scanned",
    })
    scan = ScanResult.from_dict({
        "scanner_id": "scanner", "scanner_version": "1", "ruleset_digest": DIGEST,
        "target_sha": SHA, "status": "complete", "findings": [], "errors": [], "warnings": [],
    })
    decision = PublicationDecision.from_dict({
        "decision": decision_name, "reviewer": "policy-engine", "reason_codes": ["COMPLETE_SCAN_NO_FINDINGS"],
        "approved_artifacts": ["report.json", "report.md", "index.html", "manifest.json", "checksums.txt"],
        "full_findings_public": False,
    })
    bundle = root / "bundle"
    build_report_bundle(ReportModel(target, scan, [], decision, ["test limitation"]), bundle, "owner-repo")
    return bundle


class PublishStagingTests(unittest.TestCase):
    def test_origin_snapshot_rejects_traversal(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w:") as archive:
            member = tarfile.TarInfo("../escape.txt"); member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                _extract_archive(data.getvalue(), Path(directory))
            self.assertFalse((Path(directory).parent / "escape.txt").exists())

    def test_origin_snapshot_rejects_duplicate_path(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w:") as archive:
            for content in (b"a", b"b"):
                member = tarfile.TarInfo("public/reports/file"); member.size = 1
                archive.addfile(member, io.BytesIO(content))
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                _extract_archive(data.getvalue(), Path(directory))

    def test_origin_snapshot_rejects_symlink(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w:") as archive:
            member = tarfile.TarInfo("public/reports/link"); member.type = tarfile.SYMTYPE; member.linkname = "/etc/passwd"
            archive.addfile(member)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                _extract_archive(data.getvalue(), Path(directory))

    def test_publish_stages_verified_publish_bundle_under_canonical_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "reports"
            plan = prepare_publication(destination, make_bundle(root), revision=1)
            expected = destination / "public/reports/github/owner/repo" / SHA / "r1"
            self.assertEqual(plan.destination, expected)
            self.assertEqual(len(plan.artifacts), 8)
            self.assertTrue((expected / "checksums.txt").exists())

    def test_cli_publish_pr_stages_verified_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = make_bundle(root)
            destination = root / "reports"
            env = os.environ.copy(); env["PYTHONPATH"] = "src"
            result = subprocess.run([
                sys.executable, "-m", "observatory", "publish-pr",
                "--bundle", str(bundle), "--reports-repo", str(destination), "--revision", "2",
            ], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertTrue(payload["staged"])
            self.assertTrue((destination / "public/reports/github/owner/repo" / SHA / "r2" / "report.json").exists())

    def test_create_publication_pr_runs_branch_commit_push_and_gh(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports_repo = root / "reports"
            reports_repo.mkdir()
            bundle = make_bundle(root)
            snapshot = root / "origin-snapshot"; snapshot.mkdir()
            git_outputs = iter(["", "", "", "", "", "abc123", "", "git@github.com:9batalion/coderisktools-observatory-reports.git"])
            gh_result = subprocess.CompletedProcess(["gh"], 0, "https://github.com/9batalion/coderisktools-observatory-reports/pull/99\n", "")
            with mock.patch("observatory.publishing.pr._run_git", side_effect=lambda *args: next(git_outputs)), mock.patch("observatory.publishing.pr._origin_snapshot", return_value=snapshot), mock.patch("observatory.publishing.pr.subprocess.run", return_value=gh_result):
                result = create_publication_pr(reports_repo, bundle, revision=3, branch="publish/test-r3")
            self.assertEqual(result.url, "https://github.com/9batalion/coderisktools-observatory-reports/pull/99")
            self.assertEqual(result.commit, "abc123")
            self.assertTrue(result.plan.destination.exists())

    def test_create_publication_pr_stops_on_immutability_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); reports_repo = root / "reports"; reports_repo.mkdir(); bundle = make_bundle(root)
            snapshot = root / "origin-snapshot"; snapshot.mkdir()
            outputs = iter(["", "", "", ""])
            invalid = type("Invalid", (), {"valid": False, "errors": ["existing report changed"]})()
            with mock.patch("observatory.publishing.pr._run_git", side_effect=lambda *args: next(outputs)), mock.patch("observatory.publishing.pr._origin_snapshot", return_value=snapshot), mock.patch("observatory.publishing.pr.verify_immutability", return_value=invalid):
                with self.assertRaises(PublicationError):
                    create_publication_pr(reports_repo, bundle, revision=4, branch="publish/test-r4")

    def test_publish_rejects_non_publish_decision_and_existing_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "reports"
            with self.assertRaises(PublicationError):
                prepare_publication(destination, make_bundle(root, "HOLD"), revision=1)
            prepare_publication(destination, make_bundle(root), revision=1)
            with self.assertRaises(PublicationError):
                prepare_publication(destination, make_bundle(root), revision=1)


if __name__ == "__main__":
    unittest.main()
