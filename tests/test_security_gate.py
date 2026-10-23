import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import check_nvidia_security as gate


class NvidiaSecurityGateTests(unittest.TestCase):
    def config(self, directory: str, *, baseline: str = "base") -> Path:
        path = Path(directory) / "security-baseline.json"
        path.write_text(
            json.dumps(
                {
                    "repository": "NVIDIA/product-security",
                    "baseline_commit": baseline,
                    "relevant_terms": ["GPU Operator", "DCGM"],
                }
            ),
            encoding="utf-8",
        )
        return path

    def run_check(self, files, texts=()):
        def fake_json(url):
            if url.endswith("/branches/main"):
                return {"commit": {"sha": "head"}}
            return {"status": "ahead", "files": files}

        with tempfile.TemporaryDirectory() as directory:
            with patch.object(gate, "_json", side_effect=fake_json):
                with patch.object(gate, "_text", side_effect=texts) as fetch:
                    result = gate.check(self.config(directory))
        return result, fetch

    def test_matching_baseline_passes_without_comparison(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(directory, baseline="same")
            with patch.object(
                gate, "_json", return_value={"commit": {"sha": "same"}}
            ) as fetch:
                result = gate.check(config)
        self.assertTrue(result["passed"])
        self.assertEqual(fetch.call_count, 1)

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
        result, fetch = self.run_check(files)
        self.assertTrue(result["passed"])
        fetch.assert_not_called()

    def test_relevant_changed_index_line_fails(self):
        files = [
            {
                "filename": "2026/CVE_index.md",
                "status": "modified",
                "patch": "@@ -1 +1 @@\n-| old |\n+| CVE | GPU Operator |",
            }
        ]
        result, _ = self.run_check(files)
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

    def test_non_ancestral_baseline_fails_closed(self):
        def fake_json(url):
            if url.endswith("/branches/main"):
                return {"commit": {"sha": "head"}}
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
            "/branches/main": {"commit": {"sha": "head"}},
            "/compare/base...head": {
                "status": "ahead",
                "files": [{"filename": f"partial/{i}.json", "status": "added"} for i in range(300)],
            },
            "/git/commits/base": {"sha": "base", "tree": {"sha": "1" * 40}},
            "/git/commits/head": {"sha": "head", "tree": {"sha": "2" * 40}},
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
        self.assertIn("/base/2026/6000/6000.md", fetch.call_args.args[0])

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
        self.assertTrue(any(url.endswith("/git/commits/base") for url in urls))
        self.assertTrue(any(url.endswith("/git/commits/head") for url in urls))
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
        for metadata in ({"sha": "other", "tree": {"sha": "1" * 40}}, {"sha": "base"}, {"sha": "base", "tree": {"sha": "bad"}}):
            with self.subTest(metadata=metadata):
                with self.assertRaises(ValueError):
                    self.run_tree_check([], [], overrides={"/git/commits/base": metadata})

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
            self.run_tree_check([], [], overrides={"/compare/base...head": {"status": "diverged", "files": [{}] * 300}})

    def test_fallback_text_failure_is_not_treated_as_a_clean_scan(self):
        with self.assertRaisesRegex(OSError, "text unavailable"):
            self.run_tree_check([], [self.entry("2026/6000/6000.md")], texts=OSError("text unavailable"))


if __name__ == "__main__":
    unittest.main()
