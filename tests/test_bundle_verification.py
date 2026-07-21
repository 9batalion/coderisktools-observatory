import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import unittest

from observatory.verification.bundle import verify_bundle

REQUIRED = ["report.json", "report.md", "index.html", "scan-summary.json", "publication-decision.json", "review-record.json"]


def make_bundle(root):
    root = Path(root)
    sha = "a" * 40
    report = {
        "schema_version": "1", "repository_name": "repo", "repository_url": "https://github.com/owner/repo",
        "target": {"target_id": "owner-repo", "repository_url": "https://github.com/owner/repo", "requested_ref": "main", "resolved_sha": sha, "source": "test", "selection_reason": "fixture", "license_status": "recognized", "execution_allowed": False, "publication_mode": "public-summary", "status": "scanned"},
        "scan": {"scanner_id": "scanner", "scanner_version": "1", "ruleset_digest": "sha256:" + "b" * 64, "target_sha": sha, "status": "complete", "errors": [], "warnings": [], "findings": []},
        "findings": [], "publication_decision": {"decision": "PUBLISH", "reviewer": "operator", "reason_codes": ["CLEAN"], "approved_artifacts": ["report.json"], "full_findings_public": False, "override": False, "override_reason": None},
        "limitations": ["fixture"], "disclaimer": "Evidence, not certification.",
    }
    decision = {"decision": "PUBLISH", "reviewer": "operator", "reason_codes": ["CLEAN"], "approved_artifacts": ["report.json"], "full_findings_public": False, "override": False, "override_reason": None}
    review = {"reviewer": "operator", "decision": "PUBLISH", "reason_codes": ["CLEAN"], "target_sha": sha, "manual_gate_required": True}
    (root / "report.json").write_text(json.dumps(report) + "\n")
    (root / "publication-decision.json").write_text(json.dumps(decision) + "\n")
    (root / "review-record.json").write_text(json.dumps(review) + "\n")
    (root / "scan-summary.json").write_text(json.dumps({"target_sha": sha, "status": "complete", "finding_count": 0, "error_count": 0, "warning_count": 0}) + "\n")
    for name in (set(REQUIRED) - {"report.json", "publication-decision.json", "review-record.json", "scan-summary.json"}):
        (root / name).write_text(name + "\n")
    entries = []
    for name in REQUIRED:
        data = (root / name).read_bytes()
        entries.append({"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    manifest = {"manifest_version": "1", "target_sha": "a" * 40, "artifacts": entries}
    (root / "manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")
    checksum_members = REQUIRED + ["manifest.json"]
    (root / "checksums.txt").write_text("".join(f"{hashlib.sha256((root / name).read_bytes()).hexdigest()}  {name}\n" for name in sorted(checksum_members)))


class BundleVerificationTests(unittest.TestCase):
    def test_valid_bundle_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            make_bundle(directory)
            result = verify_bundle(Path(directory))
        self.assertTrue(result.valid)
        self.assertEqual(result.errors, [])

    def test_tampering_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            make_bundle(directory)
            (Path(directory) / "report.md").write_text("tampered\n")
            result = verify_bundle(Path(directory))
        self.assertFalse(result.valid)
        self.assertTrue(any("hash" in error for error in result.errors))

    def test_schema_tampering_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            make_bundle(directory)
            report_path = Path(directory) / "report.json"
            report = json.loads(report_path.read_text())
            report["execution_allowed"] = True
            report_path.write_text(json.dumps(report))
            result = verify_bundle(Path(directory))
        self.assertFalse(result.valid)
        self.assertTrue(any("schema validation failed" in error for error in result.errors))

    def test_cli_verify_returns_machine_result(self):
        with tempfile.TemporaryDirectory() as directory:
            make_bundle(directory)
            env = os.environ.copy()
            env["PYTHONPATH"] = "src"
            completed = __import__("subprocess").run(
                [sys.executable, "-m", "observatory", "verify", directory, "--json"],
                env=env, stdout=__import__("subprocess").PIPE, text=True, check=True,
            )
        self.assertIn('"valid": true', completed.stdout)

    def test_manifest_traversal_and_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            make_bundle(directory)
            manifest_path = Path(directory) / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["artifacts"].append({"name": "../outside", "size": 0, "sha256": "0" * 64})
            manifest_path.write_text(json.dumps(manifest))
            result = verify_bundle(Path(directory))
        self.assertFalse(result.valid)
        self.assertTrue(any("unsafe" in error for error in result.errors))

        with tempfile.TemporaryDirectory() as directory:
            make_bundle(directory)
            outside = Path(directory).parent / "outside.txt"
            outside.write_text("outside")
            try:
                (Path(directory) / "link.txt").symlink_to(outside)
            except OSError:
                self.skipTest("symlink unsupported")
            result = verify_bundle(Path(directory))
        self.assertFalse(result.valid)
        self.assertTrue(any("symlink" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
