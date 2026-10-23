import contextlib
import io
import json
import unittest
from unittest.mock import patch

from nvlx.fleet_cli import main
from nvlx.security_gate import evaluate_dcgm_exporter, gate


class DcgmSecurityGateTests(unittest.TestCase):
    def test_canonical_versions_follow_numeric_floor(self):
        for version, blocked in (
            ("0.0.0", True), ("4.7.99", True), ("4.8.1", True),
            ("4.8.2", False), ("4.8.3", False), ("4.10.0", False), ("5.0.0", False),
        ):
            with self.subTest(version=version):
                finding = evaluate_dcgm_exporter(version)
                self.assertIs(finding.blocked, blocked)
                self.assertEqual(finding.cves, ("CVE-2026-47483",))
                self.assertEqual(finding.severity, "HIGH")

    def test_arbitrary_numeric_text_is_not_a_release_version(self):
        for version in (
            "release-999", "DCGM Exporter 4.8.3", "CVE-2026-99999",
            "x4.8.3", "4.8.3garbage", "4.8.3/other", "4.8.3 or 4.8.1",
        ):
            with self.subTest(version=version):
                finding = evaluate_dcgm_exporter(version)
                self.assertTrue(finding.blocked)
                self.assertIn("version invalid", finding.reason)

    def test_prerelease_and_metadata_versions_are_rejected(self):
        for version in (
            "4.8.2-rc.1", "4.8.3rc1", "4.8.3+build.1",
            "4.8.3-dev", "v4.8.3", "4.8.3-1",
        ):
            with self.subTest(version=version):
                self.assertTrue(evaluate_dcgm_exporter(version).blocked)

    def test_noncanonical_numeric_versions_are_rejected(self):
        for version in (
            "4", "4.8", "4.8.3.1", "04.8.3", "4.08.3", "4.8.03",
            "-4.8.3", "+4.8.3", "4..8.3", "\u0664.\u0668.\u0663",
        ):
            with self.subTest(version=version):
                self.assertTrue(evaluate_dcgm_exporter(version).blocked)

    def test_whitespace_and_control_characters_are_rejected(self):
        for version in (
            " 4.8.3", "4.8.3 ", "4.8.3\n", "4.8.3\t", "4.8.3\x00",
            "4.\n8.3", "\x1b[31m4.8.3",
        ):
            with self.subTest(version=version):
                finding = evaluate_dcgm_exporter(version)
                self.assertTrue(finding.blocked)
                self.assertNotIn("\x1b", finding.reason)
                self.assertNotIn("\x00", finding.reason)

    def test_container_tags_are_not_treated_as_exporter_versions(self):
        for version in (
            "4.6.0-4.8.3-distroless", "999.0.0-4.8.1-ubuntu24.04",
            "nvidia/dcgm-exporter:4.6.0-4.8.3-distroless",
            "nvidia/dcgm-exporter@sha256:" + "9" * 64,
        ):
            with self.subTest(version=version):
                self.assertTrue(evaluate_dcgm_exporter(version).blocked)

    def test_missing_and_nonstring_versions_are_blocked(self):
        for version in (None, "", False, 0, 4.83, [], {}, (4, 8, 3)):
            with self.subTest(version=version):
                finding = evaluate_dcgm_exporter(version)
                self.assertTrue(finding.blocked)
                self.assertIn("version", finding.reason)

    def test_invalid_thresholds_fail_closed(self):
        for threshold in (
            "", "release-1", "0", "4.8", "04.8.2", "4.8.2-rc.1",
            "4.8.2+build", None, False, [],
        ):
            with self.subTest(threshold=threshold):
                finding = evaluate_dcgm_exporter("4.8.3", threshold=threshold)
                self.assertTrue(finding.blocked)
                self.assertIn("minimum fixed version invalid", finding.reason)

    def test_custom_canonical_threshold_uses_all_components(self):
        for version, threshold, blocked in (
            ("4.10.0", "4.9.99", False),
            ("4.9.99", "4.10.0", True),
            ("5.0.0", "5.0.0", False),
        ):
            with self.subTest(version=version, threshold=threshold):
                self.assertIs(evaluate_dcgm_exporter(version, threshold=threshold).blocked, blocked)

    @patch("nvlx.security_gate.bulletin_reachable", return_value=True)
    def test_malformed_version_blocks_with_reachable_sources(self, reachable):
        result = gate("release-999")
        self.assertIs(result["passed"], False)
        self.assertIs(result["findings"][0]["blocked"], True)

    @patch("nvlx.security_gate.bulletin_reachable", return_value=False)
    def test_fail_open_does_not_bypass_invalid_version(self, reachable):
        result = gate("release-999", fail_closed=False)
        self.assertIs(result["passed"], False)
        self.assertIs(result["findings"][0]["blocked"], True)

    @patch("nvlx.security_gate.bulletin_reachable", return_value=False)
    def test_valid_release_retains_source_availability_policy(self, reachable):
        self.assertIs(gate("4.8.3")["passed"], False)
        self.assertIs(gate("4.8.3", fail_closed=False)["passed"], True)

    def test_cli_invalid_versions_return_failed_json_even_with_fail_open(self):
        for version in ("release-999", "4.8.2-rc.1", "4.6.0-4.8.3-distroless"):
            for available in (True, False):
                with self.subTest(version=version, available=available):
                    output = io.StringIO()
                    with (
                        patch("nvlx.security_gate.bulletin_reachable", return_value=available),
                        contextlib.redirect_stdout(output),
                    ):
                        code = main(["security-gate", "--dcgm-exporter-version", version, "--fail-open"])
                    result = json.loads(output.getvalue())
                    self.assertEqual(code, 2)
                    self.assertIs(result["passed"], False)
                    self.assertIs(result["findings"][0]["blocked"], True)
                    self.assertIn("version invalid", result["reasons"][0])

    @patch("nvlx.security_gate.bulletin_reachable", return_value=True)
    def test_cli_valid_release_returns_successful_json(self, reachable):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["security-gate", "--dcgm-exporter-version", "4.8.3"])
        self.assertEqual(code, 0)
        result = json.loads(output.getvalue())
        self.assertIs(result["passed"], True)
        self.assertIn("4.8.3", result["reasons"][0])


if __name__ == "__main__":
    unittest.main()
