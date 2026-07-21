import json
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from observatory.benchmark import BenchmarkError, load_manifest, run_benchmark
from observatory.contracts import ScanResult

DIGEST = "sha256:" + "a" * 64


class FakeAdapter:
    scanner_id = "benchmark-fake"
    def scan(self, target_path, target_sha):
        if (Path(target_path) / "secret.fixture").exists():
            finding = {
                "matched_text": "[REDACTED]", "line_content": "[REDACTED]",
                "fingerprint": "sha256:" + "b" * 64, "file": "secret.fixture",
                "rule_id": "CRT-SEC-001", "severity": "high", "confidence": "confirmed",
                "category": "secret", "type": "secret",
            }
            return ScanResult(self.scanner_id, "test", DIGEST, target_sha, "complete", [finding], [], [])
        return ScanResult(self.scanner_id, "test", DIGEST, target_sha, "complete", [], [], [])


class BenchmarkTests(unittest.TestCase):
    def manifest(self):
        return {
            "schema_version": 1,
            "benchmark_version": "0.1.0",
            "cases": [
                {"id": "clean", "files": [], "expected": {"scan_status": "complete", "finding_count": 0, "decision": "PUBLISH"}},
                {"id": "secret", "files": [{"path": "secret.fixture", "content": "synthetic"}], "expected": {"scan_status": "complete", "finding_count": 1, "decision": "HOLD"}},
            ],
        }

    def test_load_manifest_rejects_unknown_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            payload = self.manifest(); payload["unexpected"] = True
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(BenchmarkError):
                load_manifest(path)

    def test_run_benchmark_is_deterministic_and_checks_expected_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            path.write_text(json.dumps(self.manifest()), encoding="utf-8")
            first = run_benchmark(path, FakeAdapter(), DIGEST)
            second = run_benchmark(path, FakeAdapter(), DIGEST)
        self.assertEqual(first, second)
        self.assertEqual([item["decision"] for item in first], ["PUBLISH", "HOLD"])
        self.assertTrue(all(item["passed"] for item in first))

    def test_run_benchmark_rejects_ruleset_digest_mismatch(self):
        class WrongDigestAdapter(FakeAdapter):
            def scan(self, target_path, target_sha):
                result = super().scan(target_path, target_sha)
                return type(result)(result.scanner_id, result.scanner_version, "sha256:" + "f" * 64, result.target_sha, result.status, result.findings, result.errors, result.warnings)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            path.write_text(json.dumps(self.manifest()), encoding="utf-8")
            with self.assertRaises(BenchmarkError):
                run_benchmark(path, WrongDigestAdapter(), DIGEST)

    def test_run_benchmark_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            payload = self.manifest(); payload["cases"][0]["files"] = [{"path": "../escape", "content": "x"}]
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(BenchmarkError):
                run_benchmark(path, FakeAdapter(), DIGEST)


if __name__ == "__main__":
    unittest.main()
