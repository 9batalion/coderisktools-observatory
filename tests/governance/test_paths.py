import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[2] / "src"))

import unittest

from observatory.verification.paths import validate_publication_paths


class PublicationPathTests(unittest.TestCase):
    def test_only_allowed_publication_paths_pass(self):
        self.assertEqual(
            validate_publication_paths(["public/a/report.json", "operator/review.json"]),
            [],
        )

    def test_pipeline_code_change_is_rejected(self):
        self.assertEqual(
            validate_publication_paths(["public/a/report.json", "src/observatory/pipeline.py"]),
            ["src/observatory/pipeline.py"],
        )

    def test_path_traversal_is_rejected(self):
        self.assertEqual(validate_publication_paths(["public/../src/x.py"]), ["public/../src/x.py"])


if __name__ == "__main__":
    unittest.main()
