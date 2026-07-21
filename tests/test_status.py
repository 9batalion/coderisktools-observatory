import json
import tempfile
import unittest
from pathlib import Path

from observatory.status import build_status, render_status_html, write_status_page


class StatusTests(unittest.TestCase):
    def test_status_is_closed_and_contains_only_aggregates(self):
        status = build_status(
            generated_at="2026-07-21T08:00:00Z",
            build_sha="a" * 40,
            last_publication="2026-07-20T10:00:00Z",
            reports=4,
            digests=2,
            retractions=1,
            partial_scans=0,
            feed_status="healthy",
            self_scan_decision="PUBLISH",
            self_scan_findings=0,
            benchmark_passed=True,
        )
        self.assertEqual(status["counts"]["reports"], 4)
        self.assertNotIn("findings", status)
        self.assertNotIn("operator", status)
        self.assertEqual(set(status), {
            "schema_version", "generated_at", "last_build_sha", "last_publication",
            "counts", "feeds", "self_scan", "benchmark",
        })

    def test_rejects_invalid_counts_and_private_values(self):
        with self.assertRaises(ValueError):
            build_status(
                generated_at="2026-07-21T08:00:00Z", build_sha="a" * 40,
                last_publication=None, reports=-1, digests=0, retractions=0,
                partial_scans=0, feed_status="healthy", self_scan_decision="PUBLISH",
                self_scan_findings=0, benchmark_passed=True,
            )

    def test_html_escapes_values_and_is_static(self):
        status = build_status(
            generated_at="2026-07-21T08:00:00Z", build_sha="a" * 40,
            last_publication=None, reports=0, digests=0,
            retractions=0, partial_scans=0, feed_status="healthy",
            self_scan_decision="PUBLISH", self_scan_findings=0, benchmark_passed=True,
        )
        status["last_publication"] = "<script>alert(1)</script>"
        html = render_status_html(status)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertNotIn("http", html)

    def test_write_status_page_is_deterministic(self):
        status = build_status(
            generated_at="2026-07-21T08:00:00Z", build_sha="a" * 40,
            last_publication=None, reports=1, digests=0, retractions=0,
            partial_scans=0, feed_status="healthy", self_scan_decision="PUBLISH",
            self_scan_findings=0, benchmark_passed=True,
        )
        with tempfile.TemporaryDirectory() as tmp:
            first = write_status_page(Path(tmp), status)
            payload = json.loads((Path(tmp) / "status.json").read_text())
            self.assertEqual(payload, status)
            second = write_status_page(Path(tmp), status)
            self.assertEqual(first, second)
            self.assertTrue((Path(tmp) / "index.html").is_file())


if __name__ == "__main__":
    unittest.main()
