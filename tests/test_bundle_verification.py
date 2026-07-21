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
    for name in REQUIRED:
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
