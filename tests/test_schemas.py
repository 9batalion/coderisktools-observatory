import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from observatory.verification.schema import SchemaValidationError, validate_json_file


class SchemaArtifactTests(unittest.TestCase):
    def test_core_schemas_are_closed_json_objects(self):
        root = Path(__file__).parents[1] / "schemas"
        names = ["target.schema.json", "scan-result.schema.json", "normalized-finding.schema.json", "publication-decision.schema.json", "manifest.schema.json", "review-record.schema.json", "retraction.schema.json", "report.schema.json", "scan-summary.schema.json"]
        for name in names:
            with self.subTest(name=name):
                data = json.loads((root / name).read_text())
                self.assertEqual(data["type"], "object")
                self.assertFalse(data["additionalProperties"])
                self.assertTrue(data["required"])
    def test_generated_artifact_contracts_validate_and_reject_tampering(self):
        root = Path(__file__).parents[1] / "schemas"
        cases = {
            "manifest.schema.json": {"manifest_version": "1", "target_sha": "a" * 40, "artifacts": [{"name": "report.json", "size": 12, "sha256": "b" * 64}]},
            "review-record.schema.json": {"reviewer": "operator", "decision": "PUBLISH", "reason_codes": ["CLEAN"], "target_sha": "a" * 40, "manual_gate_required": True},
            "retraction.schema.json": {"head_commit": "a" * 40, "message": "withdrawn", "reason": "superseded", "report_revision": 1, "repository": "owner/repo", "retracted_at": "2026-07-21T12:00:00Z", "schema_version": "1.0", "status": "WITHDRAWN"},
            "scan-summary.schema.json": {"target_sha": "a" * 40, "status": "complete", "finding_count": 0, "error_count": 0, "warning_count": 0},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            for schema_name, value in cases.items():
                input_path = path / schema_name; input_path.write_text(json.dumps(value))
                validate_json_file(input_path, root / schema_name)
            bad = dict(cases["retraction.schema.json"], status="PUBLISH")
            bad_path = path / "bad.json"; bad_path.write_text(json.dumps(bad))
            with self.assertRaises(SchemaValidationError):
                validate_json_file(bad_path, root / "retraction.schema.json")


if __name__ == "__main__":
    unittest.main()
