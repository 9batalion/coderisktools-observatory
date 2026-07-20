import json
from pathlib import Path
import unittest


class SchemaArtifactTests(unittest.TestCase):
    def test_core_schemas_are_closed_json_objects(self):
        root = Path(__file__).parents[1] / "schemas"
        names = ["target.schema.json", "scan-result.schema.json", "normalized-finding.schema.json", "publication-decision.schema.json"]
        for name in names:
            with self.subTest(name=name):
                data = json.loads((root / name).read_text())
                self.assertEqual(data["type"], "object")
                self.assertFalse(data["additionalProperties"])
                self.assertTrue(data["required"])


if __name__ == "__main__":
    unittest.main()
