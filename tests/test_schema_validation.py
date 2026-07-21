import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import unittest

from observatory.verification.schema import SchemaValidationError, validate_json_file


class SchemaValidationTests(unittest.TestCase):
    def _target(self):
        return {
            "target_id": "owner-repo", "repository_url": "https://github.com/owner/repo",
            "requested_ref": "main", "resolved_sha": "a" * 40, "source": "operator",
            "selection_reason": "explicit", "license_status": "recognized",
            "execution_allowed": False, "publication_mode": "public-summary", "status": "candidate",
        }

    def test_valid_target_schema_passes_and_extra_property_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            schema = Path(__file__).parents[1] / "schemas/target.schema.json"
            valid = root / "valid.json"; valid.write_text(json.dumps(self._target()))
            self.assertIsNotNone(validate_json_file(valid, schema))
            invalid = root / "invalid.json"; invalid.write_text(json.dumps({**self._target(), "unexpected": True}))
            with self.assertRaises(SchemaValidationError):
                validate_json_file(invalid, schema)

    def test_cli_returns_machine_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); value = root / "value.json"; value.write_text(json.dumps(self._target()))
            schema = Path(__file__).parents[1] / "schemas/target.schema.json"
            env = os.environ.copy(); env["PYTHONPATH"] = "src"
            result = subprocess.run([sys.executable, "-m", "observatory", "validate-json", "--input", str(value), "--schema", str(schema), "--json"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)["valid"])


if __name__ == "__main__":
    unittest.main()
