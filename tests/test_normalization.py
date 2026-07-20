import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import unittest

from observatory.normalization.findings import NormalizationError, normalize_scanner_findings

SHA = "f" * 40
FP = "sha256:" + "1" * 64


class FindingNormalizationTests(unittest.TestCase):
    def test_normalizes_redacted_scanner_finding(self):
        finding = normalize_scanner_findings([{
            "type": "secret", "pattern_name": "TOKEN", "severity": "high",
            "file": "src/config.py", "line": 4, "matched_text": "[REDACTED]",
            "line_content": "[REDACTED]", "rule": "token", "rule_id": "CRT-SEC-001",
            "category": "secret", "confidence": "high",
            "remediation": "Rotate it", "fingerprint": FP,
        }], SHA, "coderisktools-secret-scanner")
        self.assertEqual(len(finding), 1)
        self.assertEqual(finding[0].visibility, "MAINTAINER_ONLY")
        self.assertEqual(finding[0].evidence_refs, [FP])
        self.assertNotIn("matched_text", finding[0].__dict__)

    def test_rejects_unredacted_or_missing_fingerprint(self):
        base = {"rule_id": "CRT-SEC-001", "severity": "high", "category": "secret", "confidence": "high", "file": "x", "line": 1, "remediation": "Rotate"}
        with self.assertRaises(NormalizationError):
            normalize_scanner_findings([{**base, "matched_text": "REAL_VALUE", "fingerprint": FP}], SHA, "scanner")
        with self.assertRaises(NormalizationError):
            normalize_scanner_findings([base], SHA, "scanner")

    def test_rejects_path_escape_and_invalid_sha(self):
        base = {"rule_id": "CRT-SEC-001", "severity": "high", "category": "secret", "confidence": "high", "file": "../outside", "line": 1, "remediation": "Rotate", "fingerprint": FP}
        with self.assertRaises(NormalizationError):
            normalize_scanner_findings([base], SHA, "scanner")


if __name__ == "__main__":
    unittest.main()
