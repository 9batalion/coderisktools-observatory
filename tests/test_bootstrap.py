import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import unittest

from observatory.contract import project_name


class BootstrapTests(unittest.TestCase):
    def test_project_contract_has_canonical_name(self):
        self.assertEqual(project_name(), "coderisktools-observatory")


if __name__ == "__main__":
    unittest.main()
