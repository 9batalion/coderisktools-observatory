import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import unittest

from observatory.publishing.immutability import verify_immutability

PREFIX = "public/reports/github/owner/repo/" + "a" * 40 + "/r1/"


class ImmutabilityTests(unittest.TestCase):
    def _trees(self):
        root = Path(tempfile.mkdtemp())
        base = root / "base"; candidate = root / "candidate"
        for tree in (base, candidate):
            path = tree / PREFIX
            path.mkdir(parents=True)
            (path / "report.json").write_text("original\n")
            (path / "checksums.txt").write_text("checksum\n")
        return root, base, candidate

    def test_cli_returns_machine_valid_result(self):
        root, base, candidate = self._trees()
        try:
            (candidate / PREFIX / "retraction.json").write_text('{"status":"WITHDRAWN"}\n')
            paths = root / "paths.txt"; paths.write_text(PREFIX + "retraction.json\n")
            env = os.environ.copy(); env["PYTHONPATH"] = "src"
            result = subprocess.run([sys.executable, "-m", "observatory", "verify-immutability", "--base", str(base), "--candidate", str(candidate), "--paths", str(paths), "--json"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)["valid"])
        finally:
            shutil.rmtree(root)

    def test_existing_report_change_is_rejected(self):
        root, base, candidate = self._trees()
        try:
            (candidate / PREFIX / "report.json").write_text("tampered\n")
            result = verify_immutability(base, candidate, [PREFIX + "report.json"])
            self.assertFalse(result.valid)
        finally:
            import shutil; shutil.rmtree(root)

    def test_new_retraction_is_allowed_but_deletion_is_rejected(self):
        root, base, candidate = self._trees()
        try:
            (candidate / PREFIX / "retraction.json").write_text('{"status":"WITHDRAWN"}\n')
            result = verify_immutability(base, candidate, [PREFIX + "retraction.json"])
            self.assertTrue(result.valid, result.errors)
            (candidate / PREFIX / "checksums.txt").unlink()
            result = verify_immutability(base, candidate, [PREFIX + "checksums.txt"])
            self.assertFalse(result.valid)
        finally:
            import shutil; shutil.rmtree(root)

    def test_new_revision_is_allowed_and_two_revisions_are_rejected(self):
        root, base, candidate = self._trees()
        try:
            sha = "b" * 40
            first = f"public/reports/github/owner/repo/{sha}/r1/report.json"
            second = f"public/reports/github/owner/repo/{sha}/r2/report.json"
            for path in (candidate / first, candidate / second):
                path.parent.mkdir(parents=True, exist_ok=True); path.write_text("new\n")
            result = verify_immutability(base, candidate, [first, second])
            self.assertFalse(result.valid)
            (candidate / second).unlink()
            result = verify_immutability(base, candidate, [first])
            self.assertTrue(result.valid, result.errors)
        finally:
            import shutil; shutil.rmtree(root)


if __name__ == "__main__":
    unittest.main()
