#!/usr/bin/env python3
"""Fail when NVIDIA changes security material relevant to nvlx-managed components."""
from __future__ import annotations

import argparse
import difflib
import json
import re
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath


API = "https://api.github.com/repos/{repo}"
RAW = "https://raw.githubusercontent.com/{repo}/{ref}/{path}"
OBJECT_SHA = re.compile(r"[0-9a-f]{40}\Z")


def _json(url: str):
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "nvlx-security-gate",
        },
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


def _text(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "nvlx-security-gate"})
    with urllib.request.urlopen(request, timeout=15) as response:
        return response.read().decode("utf-8", "replace")


def _raw_url(repo: str, ref: str, path: str) -> str:
    return RAW.format(
        repo=repo,
        ref=urllib.parse.quote(ref, safe=""),
        path=urllib.parse.quote(path, safe="/"),
    )


def _is_dedicated_bulletin(path: str) -> bool:
    """Return whether path lives below a YYYY/numeric-bulletin directory."""
    parts = PurePosixPath(path).parts
    return (
        len(parts) >= 3
        and len(parts[0]) == 4
        and parts[0].isdigit()
        and parts[1].isdigit()
    )


def _patch_changes(patch: str) -> str:
    """Extract changed lines only, excluding unified-diff file markers and context."""
    changed = []
    for line in patch.splitlines():
        if line.startswith(("+++", "---")):
            continue
        if line.startswith(("+", "-")):
            changed.append(line[1:])
    return "\n".join(changed)


def _content_changes(before: str, after: str) -> str:
    changed = []
    for line in difflib.ndiff(before.splitlines(), after.splitlines()):
        if line.startswith(("+ ", "- ")):
            changed.append(line[2:])
    return "\n".join(changed)


def _tree_files(repo: str, commit: str) -> dict[str, tuple[str, str]]:
    """Read a complete file inventory for one immutable commit, failing closed."""
    api = API.format(repo=repo)
    metadata = _json(api + "/git/commits/" + urllib.parse.quote(commit, safe=""))
    if type(metadata) is not dict or metadata.get("sha") != commit:
        raise ValueError("NVIDIA tree lookup returned a different commit")
    tree = metadata.get("tree")
    sha = tree.get("sha") if type(tree) is dict else None
    if type(sha) is not str or not OBJECT_SHA.fullmatch(sha):
        raise ValueError("NVIDIA commit did not include a valid tree SHA")

    response = _json(api + f"/git/trees/{sha}?recursive=1")
    if type(response) is not dict or response.get("truncated") is not False:
        raise RuntimeError("NVIDIA recursive tree is incomplete; review cannot proceed")
    if response.get("sha") != sha or type(response.get("tree")) is not list:
        raise ValueError("NVIDIA tree lookup returned an invalid tree")

    files = {}
    seen = set()
    for entry in response["tree"]:
        if type(entry) is not dict:
            raise ValueError("NVIDIA tree returned an invalid entry")
        path = entry.get("path")
        if (type(path) is not str or not path or "\\" in path
                or any(part in {"", ".", ".."} for part in path.split("/"))):
            raise ValueError("NVIDIA tree returned a non-canonical path")
        if path in seen:
            raise ValueError("NVIDIA tree returned a duplicate path")
        seen.add(path)
        object_sha = entry.get("sha")
        if type(object_sha) is not str or not OBJECT_SHA.fullmatch(object_sha):
            raise ValueError("NVIDIA tree returned an invalid object SHA")
        kind, mode = entry.get("type"), entry.get("mode")
        if kind == "tree" and mode == "040000":
            continue
        if kind != "blob" or mode not in {"100644", "100755", "120000"}:
            raise ValueError("NVIDIA tree contains an unsupported entry type or mode")
        if mode == "120000" and path.endswith(".md"):
            raise ValueError("NVIDIA tree contains a Markdown symlink; review cannot proceed")
        files[path] = (object_sha, mode)
    return files


def _tree_comparison_files(repo: str, baseline: str, head: str) -> list[dict[str, str]]:
    """Enumerate every changed file when GitHub's comparison list reaches its cap.

    Renames become a removal plus an addition so both versions receive review.
    No API patches are reused; aggregate deltas are reconstructed from full text.
    """
    before = _tree_files(repo, baseline)
    after = _tree_files(repo, head)
    changes = []
    for path in sorted(before.keys() | after.keys()):
        if before.get(path) == after.get(path):
            continue
        status = "added" if path not in before else "removed" if path not in after else "modified"
        changes.append({"filename": path, "status": status})
    return changes


def _inspection_text(
    change: dict[str, object], repo: str, baseline: str, head: str
) -> tuple[str, str]:
    """Return security-relevant delta text and the best source URL for a change."""
    path = change.get("filename")
    if type(path) is not str or not path:
        raise ValueError("NVIDIA comparison returned a file without a valid path")

    previous_path = change.get("previous_filename", path)
    if type(previous_path) is not str or not previous_path:
        previous_path = path
    status = change.get("status")
    head_url = _raw_url(repo, head, path)
    baseline_url = _raw_url(repo, baseline, previous_path)

    if status == "added":
        return _text(head_url), head_url
    if status == "removed":
        return _text(baseline_url), baseline_url

    # A dedicated bulletin is a security unit: any modification to one that
    # names a managed component needs review, even when the product name is
    # unchanged context around a version or severity edit.
    if _is_dedicated_bulletin(path) or _is_dedicated_bulletin(previous_path):
        before = _text(baseline_url)
        after = _text(head_url)
        return before + "\n" + after, head_url

    # Aggregate indexes contain historical references to managed products.
    # Searching their entire current contents turns every unrelated bulletin
    # into a false positive, so inspect only added and removed lines.
    patch = change.get("patch")
    if type(patch) is str:
        return _patch_changes(patch), head_url

    # GitHub may omit a patch for a large text file. Reconstruct the delta;
    # fetch failures intentionally propagate so the security gate fails closed.
    before = _text(baseline_url)
    after = _text(head_url)
    return _content_changes(before, after), head_url


def check(config_path: Path) -> dict[str, object]:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    repo = config["repository"]
    baseline = config["baseline_commit"]
    terms = tuple(config["relevant_terms"])
    if type(repo) is not str or not repo:
        raise ValueError("repository must be a non-empty string")
    if type(baseline) is not str or not baseline:
        raise ValueError("baseline_commit must be a non-empty string")
    if not terms or any(type(term) is not str or not term for term in terms):
        raise ValueError("relevant_terms must contain non-empty strings")

    branch = _json(API.format(repo=repo) + "/branches/main")
    head = branch["commit"]["sha"]
    if head == baseline:
        return {
            "passed": True,
            "baseline": baseline,
            "head": head,
            "relevant_changes": [],
            "comparison_source": "baseline",
            "changed_files": 0,
            "inspected_markdown_files": 0,
        }

    comparison = _json(API.format(repo=repo) + f"/compare/{baseline}...{head}")
    if comparison.get("status") != "ahead":
        raise RuntimeError(
            "NVIDIA security baseline is not an ancestor of upstream main "
            f"(comparison status: {comparison.get('status')!r})"
        )
    files = comparison.get("files")
    if type(files) is not list:
        raise ValueError("NVIDIA comparison did not include a file list")
    comparison_source = "compare"
    if len(files) >= 300:
        files = _tree_comparison_files(repo, baseline, head)
        comparison_source = "recursive-trees"

    hits = []
    inspected_markdown_files = 0
    for change in files:
        if type(change) is not dict:
            raise ValueError("NVIDIA comparison returned an invalid file entry")
        path = change.get("filename")
        if type(path) is not str or not path:
            raise ValueError("NVIDIA comparison returned a file without a valid path")
        previous_path = change.get("previous_filename", "")
        if "previous_filename" in change and (type(previous_path) is not str or not previous_path):
            raise ValueError("NVIDIA comparison returned an invalid previous path")
        if not (
            path.endswith(".md") or previous_path.endswith(".md")
        ):
            continue
        inspected_markdown_files += 1
        text, source_url = _inspection_text(change, repo, baseline, head)
        folded = text.casefold()
        matched = [term for term in terms if term.casefold() in folded]
        if matched:
            hits.append(
                {
                    "path": path,
                    "status": change.get("status"),
                    "terms": matched,
                    "raw_url": source_url,
                }
            )

    return {
        "passed": not hits,
        "baseline": baseline,
        "head": head,
        "relevant_changes": hits,
        "comparison_source": comparison_source,
        "changed_files": len(files),
        "inspected_markdown_files": inspected_markdown_files,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config/security-baseline.json")
    args = parser.parse_args(argv)
    try:
        result = check(Path(args.config))
    except Exception as exc:
        print(json.dumps({"passed": False, "error": str(exc)}, indent=2))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
