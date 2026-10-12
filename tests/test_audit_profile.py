import contextlib
import importlib.util
import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "audit_profile", Path(__file__).resolve().parents[1] / "scripts/audit_profile.py"
)
audit_profile = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit_profile)


class ProfileAuditTests(unittest.TestCase):
    def setUp(self):
        self.output = io.StringIO()
        self.stdout = contextlib.redirect_stdout(self.output)
        self.stderr = contextlib.redirect_stderr(self.output)
        self.stdout.__enter__()
        self.stderr.__enter__()
        self.addCleanup(self.stdout.__exit__, None, None, None)
        self.addCleanup(self.stderr.__exit__, None, None, None)

    def links(self, profile):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text(profile, encoding="utf-8")
            result = audit_profile.Audit()
            with patch.object(audit_profile, "ROOT", root):
                audit_profile.audit_profile_links(result)
            return result.failures

    def test_current_profile_is_reviewed(self):
        profile = (audit_profile.ROOT / "README.md").read_text(encoding="utf-8")
        self.assertEqual(self.links(profile), [])

    def test_new_markdown_recommendation_requires_review(self):
        self.assertTrue(self.links("[New](https://invalid.example/nonexistent)"))

    def test_reference_and_html_links_require_review(self):
        for profile in (
            "[New][ref]\n[ref]: https://invalid.example/",
            '<a href="https://invalid.example/">New</a>',
        ):
            with self.subTest(profile=profile):
                self.assertTrue(self.links(profile))

    def test_withheld_github_link_cannot_hide_behind_case_or_slash(self):
        self.assertTrue(self.links(
            "[Portfolio](https://GITHUB.COM/xjm-FREE/iOS-apps-portfolio/)"
        ))

    def test_http_query_and_credential_variants_are_not_approved(self):
        for url in (
            "http://tinyweblab.com",
            "https://tinyweblab.com?redirect=elsewhere",
            "https://user:password@tinyweblab.com",
            "https://tinyweblab.com.invalid.example",
        ):
            with self.subTest(url=url):
                self.assertTrue(self.links(f"[Work]({url})"))
        self.assertNotIn("password", self.output.getvalue())

    def test_root_trailing_slash_is_approved(self):
        self.assertEqual(self.links("[Work](https://tinyweblab.com/)"), [])

    def test_unsupported_markdown_scheme_is_rejected(self):
        self.assertTrue(self.links("[Work](javascript:alert(1))"))

    def test_malformed_url_is_reported(self):
        self.assertTrue(self.links("[Work](https://[broken)"))

    def surface(self, html):
        result = audit_profile.Audit()
        with patch.object(audit_profile, "request_text", return_value=html):
            audit_profile.audit_surfaces(result)
        return result.failures

    def test_current_title_is_accepted(self):
        self.assertEqual(self.surface(
            "<TITLE>未完待续 · 这一刻，还来得及</TITLE>"
        ), [])

    def test_old_site_title_is_rejected(self):
        self.assertTrue(self.surface("<title>Tiny Web Lab</title>"))

    def test_marker_in_body_does_not_validate_a_different_site(self):
        self.assertTrue(self.surface(
            "<title>Domain for sale</title><p>未完待续</p>"
        ))

    def test_timeout_is_a_request_failure(self):
        with patch.object(audit_profile.subprocess, "run", side_effect=
                          subprocess.TimeoutExpired("curl", 130)):
            with self.assertRaises(RuntimeError):
                audit_profile.request_bytes("https://tinyweblab.com")

    def test_failed_request_is_accumulated(self):
        result = audit_profile.Audit()
        with patch.object(audit_profile, "request_text", side_effect=RuntimeError):
            audit_profile.audit_surfaces(result)
        self.assertEqual(len(result.failures), 1)

    def package(self, payloads):
        result = audit_profile.Audit()
        with patch.object(audit_profile, "request_json", side_effect=payloads) as request:
            audit_profile.audit_package(result)
        return result, request

    def test_npm_metadata_is_checked_against_release_tag(self):
        result, request = self.package([
            {"name": "claude-agent-ledger", "version": "0.7.2",
             "dist": {"tarball": "https://registry.npmjs.org/package.tgz"}},
            {"name": "claude-agent-ledger", "version": "0.7.2"},
        ])
        self.assertEqual(result.failures, [])
        self.assertIn("/v0.7.2/package.json", request.call_args_list[1].args[0])
        self.assertIn("installation not tested", self.output.getvalue())
        self.assertNotIn("installable", self.output.getvalue())

    def test_npm_tag_version_mismatch_fails(self):
        result, _ = self.package([
            {"name": "claude-agent-ledger", "version": "0.7.2"},
            {"name": "claude-agent-ledger", "version": "0.7.1"},
        ])
        self.assertTrue(result.failures)

    def test_invalid_npm_version_is_not_used_as_a_url(self):
        result, request = self.package([
            {"name": "claude-agent-ledger", "version": "../main"},
        ])
        self.assertTrue(result.failures)
        self.assertEqual(request.call_count, 1)

    def test_missing_npm_archive_fails(self):
        result, _ = self.package([
            {"name": "claude-agent-ledger", "version": "0.7.2"},
            {"name": "claude-agent-ledger", "version": "0.7.2"},
        ])
        self.assertTrue(result.failures)


if __name__ == "__main__":
    unittest.main()
