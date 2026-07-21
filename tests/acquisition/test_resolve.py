import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[2] / "src"))

import unittest

from observatory.acquisition.resolve import ResolutionError, resolve_github_target

SHA = "c" * 40


class ResolveTargetTests(unittest.TestCase):
    def test_resolves_ref_through_injected_resolver(self):
        target = resolve_github_target(
            "https://github.com/owner/repo",
            "main",
            lambda url, ref: SHA,
        )
        self.assertEqual(target.repository_url, "https://github.com/owner/repo")
        self.assertEqual(target.resolved_sha, SHA)
        self.assertFalse(target.execution_allowed)

    def test_rejects_credentials_and_non_github_urls(self):
        for url in (
            "https://user:pass@github.com/owner/repo",
            "http://github.com/owner/repo",
            "https://gitlab.com/owner/repo",
            "https://github.com/owner/repo/../../x",
        ):
            with self.subTest(url=url):
                with self.assertRaises(ResolutionError):
                    resolve_github_target(url, "main", lambda *_: SHA)

    def test_rejects_short_or_moving_resolution(self):
        with self.assertRaises(ResolutionError):
            resolve_github_target("https://github.com/owner/repo", "main", lambda *_: "abc")
        with self.assertRaises(ResolutionError):
            resolve_github_target("https://github.com/owner/repo", "main", lambda *_: None)


if __name__ == "__main__":
    unittest.main()
