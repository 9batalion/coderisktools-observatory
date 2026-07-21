import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import unittest

from observatory.contracts import Target
from observatory.target_registry import RegistryError, add_target, load_targets

SHA = "7" * 40


def target(sha=SHA, ref="main"):
    return Target.from_dict({
        "target_id": "owner-repo", "repository_url": "https://github.com/owner/repo",
        "requested_ref": ref, "resolved_sha": sha, "source": "operator",
        "selection_reason": "explicit exact SHA", "license_status": "unknown",
        "execution_allowed": False, "publication_mode": "public-summary", "status": "candidate",
    })


class TargetRegistryTests(unittest.TestCase):
    def test_add_and_load_target_as_jsonl(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "targets.jsonl"
            add_target(path, target())
            self.assertEqual(load_targets(path), [target()])
            self.assertEqual(len(path.read_text().splitlines()), 1)

    def test_duplicate_exact_target_is_idempotent_but_sha_conflict_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "targets.jsonl"
            add_target(path, target())
            add_target(path, target())
            with self.assertRaises(RegistryError):
                add_target(path, target("8" * 40))
            self.assertEqual(len(load_targets(path)), 1)

    def test_cli_target_add_writes_exact_sha_record(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = Path(directory) / "targets.jsonl"
            env = os.environ.copy()
            env["PYTHONPATH"] = "src"
            completed = subprocess.run([
                sys.executable, "-m", "observatory", "target", "add",
                "--repository-url", "https://github.com/owner/repo", "--ref", "main",
                "--sha", SHA, "--registry", str(registry), "--json",
            ], env=env, stdout=subprocess.PIPE, text=True, check=True)
            self.assertIn(SHA, completed.stdout)
            self.assertEqual(load_targets(registry)[0].resolved_sha, SHA)

    def test_malformed_registry_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "targets.jsonl"
            path.write_text('{"broken":\n')
            with self.assertRaises(RegistryError):
                load_targets(path)


if __name__ == "__main__":
    unittest.main()
