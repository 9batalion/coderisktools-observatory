import os
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[2] / "src"))

import unittest

from observatory.acquisition.clone import AcquisitionError, AcquisitionLimits, acquire_repository


class SafeAcquisitionTests(unittest.TestCase):
    def _source_repo(self):
        root = Path(tempfile.mkdtemp())
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
        (root / "README.md").write_text("synthetic fixture\n")
        subprocess.run(["git", "-C", str(root), "add", "README.md"], check=True)
        subprocess.run(["git", "-C", str(root), "commit", "-qm", "fixture"], check=True)
        sha = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
        return root, sha

    def test_acquires_exact_sha_without_hooks(self):
        source, sha = self._source_repo()
        workspace = Path(tempfile.mkdtemp())
        result = acquire_repository(str(source), sha, workspace, AcquisitionLimits(max_files=10))
        self.assertEqual(result.resolved_sha, sha)
        self.assertEqual((result.path / "README.md").read_text(), "synthetic fixture\n")
        self.assertFalse((result.path / ".git" / "hooks").is_symlink())

    def test_rejects_moving_or_wrong_sha(self):
        source, sha = self._source_repo()
        workspace = Path(tempfile.mkdtemp())
        with self.assertRaises(AcquisitionError):
            acquire_repository(str(source), "a" * 40, workspace)
        with self.assertRaises(AcquisitionError):
            acquire_repository(str(source), "main", workspace)

    def test_size_limit_fails_closed(self):
        source, sha = self._source_repo()
        (source / "large.txt").write_text("x" * 100)
        subprocess.run(["git", "-C", str(source), "add", "large.txt"], check=True)
        subprocess.run(["git", "-C", str(source), "commit", "-qm", "large"], check=True)
        sha = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
        with self.assertRaises(AcquisitionError):
            acquire_repository(str(source), sha, Path(tempfile.mkdtemp()), AcquisitionLimits(max_file_bytes=10))


if __name__ == "__main__":
    unittest.main()
