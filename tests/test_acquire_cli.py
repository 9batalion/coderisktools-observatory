import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import unittest


def fixture_repo():
    root = Path(tempfile.mkdtemp())
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "acquire@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "Acquire"], check=True)
    (root / "README.md").write_text("fixture\n")
    subprocess.run(["git", "-C", str(root), "add", "README.md"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "fixture"], check=True)
    sha = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    return root, sha


class AcquireCommandTests(unittest.TestCase):
    def test_acquire_returns_exact_sha_and_keeps_workspace_artifact(self):
        source, sha = fixture_repo()
        with tempfile.TemporaryDirectory() as workspace:
            env = os.environ.copy()
            env["PYTHONPATH"] = "src"
            result = subprocess.run([
                sys.executable, "-m", "observatory", "acquire",
                "--source", str(source), "--sha", sha,
                "--workspace", workspace, "--json",
            ], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["resolved_sha"], sha)
            acquired = Path(payload["path"])
            self.assertTrue(acquired.is_dir())
            self.assertEqual((acquired / "README.md").read_text(), "fixture\n")

    def test_acquire_rejects_short_sha(self):
        source, _ = fixture_repo()
        with tempfile.TemporaryDirectory() as workspace:
            env = os.environ.copy()
            env["PYTHONPATH"] = "src"
            result = subprocess.run([
                sys.executable, "-m", "observatory", "acquire",
                "--source", str(source), "--sha", "abc", "--workspace", workspace,
            ], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(result.returncode, 3)
            self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
