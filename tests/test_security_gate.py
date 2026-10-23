import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import check_nvidia_security as gate


class NvidiaSecurityGateTests(unittest.TestCase):
    BASE = "b" * 40
    HEAD = "c" * 40

    def config(self, directory: str, *, baseline: str = BASE) -> Path:
        path = Path(directory) / "security-baseline.json"
        value = self.valid_config()
        value["baseline_commit"] = baseline
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def run_check(self, files, texts=()):
        def fake_json(url):
            if url.endswith("/branches/main"):
                return {"commit": {"sha": self.HEAD}}
            return {"status": "ahead", "files": files}

        with tempfile.TemporaryDirectory() as directory:
            with patch.object(gate, "_json", side_effect=fake_json):
                with patch.object(gate, "_text", side_effect=texts) as fetch:
                    result = gate.check(self.config(directory))
        return result, fetch

    def test_matching_baseline_passes_without_comparison(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(directory)
            with patch.object(
                gate, "_json", return_value={"commit": {"sha": self.BASE}}
            ) as fetch:
                result = gate.check(config)
        self.assertTrue(result["passed"])
        self.assertEqual(fetch.call_count, 1)

    def valid_config(self):
        return {
            "repository": "NVIDIA/product-security",
            "baseline_commit": self.BASE,
            "relevant_terms": ["GPU Operator", "DCGM"],
        }

    def assert_config_rejected(self, value):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "security-baseline.json"
            config.write_text(json.dumps(value), encoding="utf-8")
            with (
                patch.object(gate, "_json", return_value={"commit": {"sha": self.BASE}}) as fetch,
                patch.object(gate, "_text") as text_fetch,
            ):
                with self.assertRaises(ValueError):
                    gate.check(config)
                fetch.assert_not_called()
                text_fetch.assert_not_called()

    def test_string_terms_are_rejected_before_network_access(self):
        config = self.valid_config()
        config["relevant_terms"] = "GPU Operator"
        self.assert_config_rejected(config)

    def test_object_terms_are_rejected_before_network_access(self):
        config = self.valid_config()
        config["relevant_terms"] = {"GPU Operator": "unexpected value"}
        self.assert_config_rejected(config)

    def test_empty_or_non_list_terms_are_rejected(self):
        for terms in ([], {}, None, True, 0):
            with self.subTest(terms=terms):
                config = self.valid_config()
                config["relevant_terms"] = terms
                self.assert_config_rejected(config)

    def test_blank_padded_control_or_non_string_terms_are_rejected(self):
        for term in (
            "", " ", "\t", " DCGM", "DCGM ", "GPU\nOperator", "DCGM\x00", "DCGM\x7f",
            None, False, 42, [], {},
        ):
            with self.subTest(term=term):
                config = self.valid_config()
                config["relevant_terms"] = ["GPU Operator", term]
                self.assert_config_rejected(config)

    def test_repository_requires_a_single_owner_and_name(self):
        for repo in (
            None, False, 42, "", "NVIDIA", "NVIDIA/", "/product-security",
            "NVIDIA/product-security/extra", "NVIDIA/..", "../product-security", "NVIDIA/.",
            "https://github.com/NVIDIA/product-security", "NVIDIA/product-security?ref=main",
            "NVIDIA/product-security#fragment", "NVIDIA/product%2fsecurity",
            "NVIDIA\\product-security", " NVIDIA/product-security", "NVIDIA/product-security\n",
        ):
            with self.subTest(repo=repo):
                config = self.valid_config()
                config["repository"] = repo
                self.assert_config_rejected(config)

    def test_baseline_requires_a_full_canonical_commit_sha(self):
        for baseline in (
            None, False, 42, "", "main", "a" * 39, "a" * 41, "A" * 40,
            "g" * 40, " " * 40, self.BASE + "\n", "../" + self.BASE,
        ):
            with self.subTest(baseline=baseline):
                config = self.valid_config()
                config["baseline_commit"] = baseline
                self.assert_config_rejected(config)

    def test_missing_required_config_fields_are_rejected(self):
        for field in self.valid_config():
            with self.subTest(field=field):
                config = self.valid_config()
                del config[field]
                self.assert_config_rejected(config)

    def test_non_object_config_is_rejected(self):
        for config in (None, [], "configuration", 42, True):
            with self.subTest(config=config):
                self.assert_config_rejected(config)

    def test_duplicate_config_keys_are_rejected_before_network_access(self):
        for field, value in self.valid_config().items():
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                config = Path(directory) / "security-baseline.json"
                original = json.dumps(self.valid_config())
                duplicate = original[:-1] + f", {json.dumps(field)}: {json.dumps(value)}}}"
                config.write_text(duplicate, encoding="utf-8")
                with patch.object(gate, "_json") as fetch:
                    with self.assertRaisesRegex(ValueError, "duplicate"):
                        gate.check(config)
                    fetch.assert_not_called()

    def test_upstream_head_must_be_a_full_canonical_commit_sha(self):
        branches = [None, [], {}, {"commit": None}, {"commit": []}]
        branches += [
            {"commit": {"sha": sha}}
            for sha in (None, False, 42, "", "main", "c" * 39, "C" * 40, self.HEAD + "\n")
        ]
        for branch in branches:
            with self.subTest(branch=branch), tempfile.TemporaryDirectory() as directory:
                with (
                    patch.object(gate, "_json", return_value=branch) as fetch,
                    patch.object(gate, "_text") as text_fetch,
                ):
                    with self.assertRaisesRegex(ValueError, "commit SHA"):
                        gate.check(self.config(directory))
                    self.assertEqual(fetch.call_count, 1)
                    text_fetch.assert_not_called()

    def test_cli_reports_config_errors_as_failed_json_without_network_access(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(directory)
            invalid = self.valid_config()
            invalid["relevant_terms"] = "DCGM"
            config.write_text(json.dumps(invalid), encoding="utf-8")
            output = io.StringIO()
            with patch.object(gate, "_json") as fetch, contextlib.redirect_stdout(output):
                result = gate.main(["--config", str(config)])
            fetch.assert_not_called()
        self.assertEqual(result, 2)
        payload = json.loads(output.getvalue())
        self.assertIs(payload["passed"], False)
        self.assertIn("relevant_terms", payload["error"])
        self.assertNotIn("Traceback", output.getvalue())

    def test_valid_custom_repository_and_review_metadata_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(directory)
            value = self.valid_config()
            value["repository"] = "example-owner/security.bulletins_2026"
            value["review"] = {"date": "2026-10-23"}
            config.write_text(json.dumps(value), encoding="utf-8")
            with patch.object(
                gate, "_json", return_value={"commit": {"sha": self.BASE}}
            ) as fetch:
                result = gate.check(config)
        self.assertTrue(result["passed"])
        fetch.assert_called_once_with(
            "https://api.github.com/repos/example-owner/security.bulletins_2026/branches/main"
        )

    def test_unrelated_index_addition_ignores_relevant_context(self):
        files = [
            {
                "filename": "2026/CVE_index.md",
                "status": "modified",
                "patch": (
                    "@@ -10,2 +10,3 @@\n"
                    " | old | NVIDIA DCGM |\n"
                    "+| new | Megatron Bridge |"
                ),
            }
        ]
        result, fetch = self.run_check(
            files, texts=["| old | NVIDIA DCGM |", "| old | NVIDIA DCGM |\n| new | Megatron Bridge |"],
        )
        self.assertTrue(result["passed"])
        self.assertEqual(fetch.call_count, 2)

    def test_relevant_changed_index_line_fails(self):
        files = [
            {
                "filename": "2026/CVE_index.md",
                "status": "modified",
                "patch": "@@ -1 +1 @@\n-| old |\n+| CVE | GPU Operator |",
            }
        ]
        result, _ = self.run_check(files, texts=["| old |", "| CVE | GPU Operator |"])
        self.assertFalse(result["passed"])
        self.assertEqual(result["relevant_changes"][0]["terms"], ["GPU Operator"])

    def test_unrelated_added_bulletin_passes(self):
        files = [{"filename": "2026/5868/5868.md", "status": "added"}]
        result, _ = self.run_check(files, texts=["Megatron Bridge 0.5.1"])
        self.assertTrue(result["passed"])

    def test_relevant_added_bulletin_fails(self):
        files = [{"filename": "2026/6000/6000.md", "status": "added"}]
        result, _ = self.run_check(files, texts=["NVIDIA GPU Operator update"])
        self.assertFalse(result["passed"])
        self.assertEqual(result["relevant_changes"][0]["path"], "2026/6000/6000.md")

    def test_dedicated_bulletin_change_uses_full_context(self):
        files = [
            {
                "filename": "2026/6000/6000.md",
                "status": "modified",
                "patch": "@@ -8 +8 @@\n-1.0\n+1.1",
            }
        ]
        result, fetch = self.run_check(
            files,
            texts=["GPU Operator\nAffected: 1.0", "GPU Operator\nFixed: 1.1"],
        )
        self.assertFalse(result["passed"])
        self.assertEqual(fetch.call_count, 2)

    def test_missing_aggregate_patch_is_reconstructed(self):
        files = [{"filename": "2026/README.md", "status": "modified"}]
        result, fetch = self.run_check(
            files,
            texts=["Megatron Bridge", "Megatron Bridge\nGPU Operator"],
        )
        self.assertFalse(result["passed"])
        self.assertEqual(fetch.call_count, 2)

    def test_incomplete_aggregate_patch_cannot_hide_relevant_changes(self):
        files = [{
            "filename": "2026/README.md", "status": "modified",
            "patch": "@@ -1 +1,3 @@\n old entry\n+unrelated entry",
        }]
        result, fetch = self.run_check(
            files, texts=["old entry", "old entry\nunrelated entry\nGPU Operator"],
        )
        self.assertFalse(result["passed"])
        self.assertEqual(result["relevant_changes"][0]["terms"], ["GPU Operator"])
        self.assertEqual(fetch.call_count, 2)

    def test_empty_or_malformed_aggregate_patch_still_requires_full_contents(self):
        for snippet in ("", "@@ -1 +1 @@", "not a patch"):
            with self.subTest(patch=snippet):
                files = [{"filename": "2026/README.md", "status": "modified", "patch": snippet}]
                result, fetch = self.run_check(files, texts=["old entry", "DCGM update"])
                self.assertFalse(result["passed"])
                self.assertEqual(fetch.call_count, 2)

    def test_marker_like_content_lines_are_inspected_on_addition_and_removal(self):
        for before, after, snippet in (
            ("", "++DCGM", "@@ -0,0 +1 @@\n+++DCGM"),
            ("--GPU Operator", "", "@@ -1 +0,0 @@\n---GPU Operator"),
        ):
            with self.subTest(before=before, after=after):
                files = [{"filename": "2026/README.md", "status": "modified", "patch": snippet}]
                result, fetch = self.run_check(files, texts=[before, after])
                self.assertFalse(result["passed"])
                self.assertEqual(fetch.call_count, 2)

    def test_patch_only_references_do_not_override_actual_aggregate_delta(self):
        files = [{
            "filename": "2026/README.md", "status": "modified",
            "patch": "@@ -1 +1 @@\n+GPU Operator",
        }]
        result, fetch = self.run_check(
            files, texts=["historical GPU Operator", "historical GPU Operator\nnew unrelated entry"],
        )
        self.assertTrue(result["passed"])
        self.assertEqual(result["relevant_changes"], [])
        self.assertEqual(fetch.call_count, 2)

    def test_aggregate_contents_are_fetched_at_pinned_commits_with_quoted_paths(self):
        files = [{"filename": "2026/Release Notes.md", "status": "modified", "patch": ""}]
        result, fetch = self.run_check(files, texts=["old entry", "DCGM update"])
        self.assertFalse(result["passed"])
        self.assertEqual([call.args[0] for call in fetch.call_args_list], [
            f"https://raw.githubusercontent.com/NVIDIA/product-security/{self.BASE}/2026/Release%20Notes.md",
            f"https://raw.githubusercontent.com/NVIDIA/product-security/{self.HEAD}/2026/Release%20Notes.md",
        ])
        self.assertEqual(result["relevant_changes"][0]["raw_url"], fetch.call_args.args[0])

    def test_aggregate_fetch_failures_fail_closed_even_when_patch_is_available(self):
        files = [{
            "filename": "2026/README.md", "status": "modified",
            "patch": "@@ -1 +1 @@\n-old entry\n+unrelated entry",
        }]
        for texts in (
            [OSError("baseline unavailable")],
            ["old entry", OSError("head unavailable")],
        ):
            with self.subTest(texts=texts):
                with self.assertRaisesRegex(OSError, "unavailable"):
                    self.run_check(files, texts=texts)

    def test_renamed_aggregate_uses_both_paths_even_when_extension_changes(self):
        for previous, current in (
            ("2026/old.md", "2026/new.md"),
            ("2026/old.md", "2026/new.txt"),
            ("2026/old.txt", "2026/new.md"),
        ):
            with self.subTest(previous=previous, current=current):
                files = [{
                    "filename": current, "previous_filename": previous,
                    "status": "renamed", "patch": "",
                }]
                result, fetch = self.run_check(files, texts=["DCGM entry", "unrelated entry"])
                self.assertFalse(result["passed"])
                self.assertEqual([call.args[0] for call in fetch.call_args_list], [
                    f"https://raw.githubusercontent.com/NVIDIA/product-security/{self.BASE}/{previous}",
                    f"https://raw.githubusercontent.com/NVIDIA/product-security/{self.HEAD}/{current}",
                ])
                self.assertEqual(result["inspected_markdown_files"], 1)

    def test_non_ancestral_baseline_fails_closed(self):
        def fake_json(url):
            if url.endswith("/branches/main"):
                return {"commit": {"sha": self.HEAD}}
            return {"status": "diverged", "files": []}

        with tempfile.TemporaryDirectory() as directory:
            with patch.object(gate, "_json", side_effect=fake_json):
                with self.assertRaisesRegex(RuntimeError, "not an ancestor"):
                    gate.check(self.config(directory))

    def test_text_fetch_failure_propagates(self):
        files = [{"filename": "2026/6000/6000.md", "status": "added"}]
        with self.assertRaisesRegex(OSError, "network unavailable"):
            self.run_check(files, texts=OSError("network unavailable"))

    def test_invalid_comparison_paths_fail_closed(self):
        for entry in ({}, {"filename": None}, {"filename": ""}, {"filename": "data.json", "previous_filename": None}):
            with self.subTest(entry=entry):
                with self.assertRaises(ValueError):
                    self.run_check([entry])

    @staticmethod
    def entry(path, sha="a" * 40, *, mode="100644", kind="blob"):
        return {"path": path, "sha": sha, "mode": mode, "type": kind}

    def run_tree_check(self, before, after, texts=(), *, overrides=None):
        api = gate.API.format(repo="NVIDIA/product-security")
        responses = {
            "/branches/main": {"commit": {"sha": self.HEAD}},
            f"/compare/{self.BASE}...{self.HEAD}": {
                "status": "ahead",
                "files": [{"filename": f"partial/{i}.json", "status": "added"} for i in range(300)],
            },
            f"/git/commits/{self.BASE}": {"sha": self.BASE, "tree": {"sha": "1" * 40}},
            f"/git/commits/{self.HEAD}": {"sha": self.HEAD, "tree": {"sha": "2" * 40}},
            f"/git/trees/{'1' * 40}?recursive=1": {"sha": "1" * 40, "tree": before, "truncated": False},
            f"/git/trees/{'2' * 40}?recursive=1": {"sha": "2" * 40, "tree": after, "truncated": False},
        }
        responses.update(overrides or {})

        def fake_json(url):
            if not url.startswith(api):
                raise AssertionError(f"unexpected repository URL: {url}")
            result = responses[url[len(api):]]
            if isinstance(result, Exception):
                raise result
            return result

        with tempfile.TemporaryDirectory() as directory:
            with patch.object(gate, "_json", side_effect=fake_json) as json_fetch:
                with patch.object(gate, "_text", side_effect=texts) as text_fetch:
                    result = gate.check(self.config(directory))
        return result, json_fetch, text_fetch

    def test_capped_comparison_inspects_every_markdown_beyond_300(self):
        after = [self.entry(f"2026/{i}/README.md") for i in range(301)]
        result, _, fetch = self.run_tree_check([], after, ["unrelated"] * 300 + ["GPU Operator"])
        self.assertFalse(result["passed"])
        self.assertEqual(result["comparison_source"], "recursive-trees")
        self.assertEqual(result["changed_files"], 301)
        self.assertEqual(result["inspected_markdown_files"], 301)
        self.assertEqual(fetch.call_count, 301)
        self.assertEqual(len(result["relevant_changes"]), 1)

    def test_capped_unrelated_changes_pass_after_complete_inspection(self):
        after = [self.entry(f"data/{i}.json") for i in range(350)]
        after.append(self.entry("2026/6000/6000.md"))
        result, _, fetch = self.run_tree_check([], after, ["unrelated product"])
        self.assertTrue(result["passed"])
        self.assertEqual((result["changed_files"], result["inspected_markdown_files"]), (351, 1))
        self.assertEqual(fetch.call_count, 1)

    def test_tree_fallback_reviews_removed_bulletin_at_baseline(self):
        result, _, fetch = self.run_tree_check([self.entry("2026/6000/6000.md")], [], ["DCGM"])
        self.assertFalse(result["passed"])
        self.assertEqual(result["relevant_changes"][0]["status"], "removed")
        self.assertIn(f"/{self.BASE}/2026/6000/6000.md", fetch.call_args.args[0])

    def test_tree_fallback_keeps_full_dedicated_bulletin_context(self):
        before = [self.entry("2026/6000/6000.md")]
        after = [self.entry("2026/6000/6000.md", "b" * 40)]
        result, _, fetch = self.run_tree_check(before, after, ["DCGM\nFixed: 1.0", "DCGM\nFixed: 1.1"])
        self.assertFalse(result["passed"])
        self.assertEqual(fetch.call_count, 2)

    def test_tree_fallback_reconstructs_aggregate_delta_without_context_false_positive(self):
        before = [self.entry("2026/CVE_index.md")]
        after = [self.entry("2026/CVE_index.md", "b" * 40)]
        result, _, fetch = self.run_tree_check(before, after, ["old DCGM\nold entry", "old DCGM\nold entry\nnew unrelated entry"])
        self.assertTrue(result["passed"])
        self.assertEqual(fetch.call_count, 2)

    def test_tree_fallback_reviews_both_sides_of_renames(self):
        before = [self.entry("2026/6000/old.md")]
        after = [self.entry("2026/6000/new.md")]
        result, _, fetch = self.run_tree_check(before, after, ["GPU Operator", "GPU Operator"])
        self.assertFalse(result["passed"])
        self.assertEqual({change["status"] for change in result["relevant_changes"]}, {"added", "removed"})
        self.assertEqual(fetch.call_count, 2)

    def test_tree_fallback_excludes_unchanged_files_and_uses_pinned_commits(self):
        entries = [self.entry("2026/6000/6000.md")]
        result, fetch, text_fetch = self.run_tree_check(entries, entries)
        self.assertTrue(result["passed"])
        self.assertEqual(result["changed_files"], 0)
        text_fetch.assert_not_called()
        urls = [call.args[0] for call in fetch.call_args_list]
        self.assertEqual(sum(url.endswith("/branches/main") for url in urls), 1)
        self.assertTrue(any(url.endswith(f"/git/commits/{self.BASE}") for url in urls))
        self.assertTrue(any(url.endswith(f"/git/commits/{self.HEAD}") for url in urls))
        self.assertFalse(any("/git/trees/main" in url for url in urls))

    def test_truncated_or_unconfirmed_trees_fail_closed(self):
        for tree_sha in ("1" * 40, "2" * 40):
            for truncated in (True, None, "false", 0):
                with self.subTest(tree=tree_sha, truncated=truncated):
                    response = {"sha": tree_sha, "tree": [], "truncated": truncated}
                    with self.assertRaisesRegex(RuntimeError, "incomplete"):
                        self.run_tree_check([], [], overrides={f"/git/trees/{tree_sha}?recursive=1": response})

    def test_wrong_or_malformed_tree_response_fails_closed(self):
        for response in (
            {"sha": "9" * 40, "tree": [], "truncated": False},
            {"sha": "1" * 40, "tree": {}, "truncated": False},
        ):
            with self.subTest(response=response):
                with self.assertRaisesRegex(ValueError, "invalid tree"):
                    self.run_tree_check([], [], overrides={f"/git/trees/{'1' * 40}?recursive=1": response})

    def test_wrong_commit_or_missing_tree_sha_fails_closed(self):
        for metadata in ({"sha": "other", "tree": {"sha": "1" * 40}}, {"sha": self.BASE}, {"sha": self.BASE, "tree": {"sha": "bad"}}):
            with self.subTest(metadata=metadata):
                with self.assertRaises(ValueError):
                    self.run_tree_check([], [], overrides={f"/git/commits/{self.BASE}": metadata})

    def test_invalid_tree_entries_fail_closed(self):
        for entries in (
            [None],
            [self.entry("../bulletin.md")],
            [self.entry("/bulletin.md")],
            [self.entry("folder//bulletin.md")],
            [self.entry("folder\\bulletin.md")],
            [self.entry("bulletin.md", "invalid")],
            [self.entry("bulletin.md"), self.entry("bulletin.md", "b" * 40)],
            [self.entry("submodule", kind="commit", mode="160000")],
            [self.entry("bulletin.md", mode="120000")],
            [self.entry("bulletin.md", mode="040000")],
        ):
            with self.subTest(entries=entries):
                with self.assertRaises(ValueError):
                    self.run_tree_check(entries, [])

    def test_tree_fetch_failure_propagates(self):
        with self.assertRaisesRegex(OSError, "network unavailable"):
            self.run_tree_check([], [], overrides={f"/git/trees/{'2' * 40}?recursive=1": OSError("network unavailable")})

    def test_non_ancestral_capped_comparison_never_reaches_tree_fallback(self):
        with self.assertRaisesRegex(RuntimeError, "not an ancestor"):
            self.run_tree_check([], [], overrides={f"/compare/{self.BASE}...{self.HEAD}": {"status": "diverged", "files": [{}] * 300}})

    def test_fallback_text_failure_is_not_treated_as_a_clean_scan(self):
        with self.assertRaisesRegex(OSError, "text unavailable"):
            self.run_tree_check([], [self.entry("2026/6000/6000.md")], texts=OSError("text unavailable"))


if __name__ == "__main__":
    unittest.main()
