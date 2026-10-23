import contextlib
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import tarfile
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/repro_release.py"
SPEC = importlib.util.spec_from_file_location("repro_release", SCRIPT)
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class ReproducibleReleaseTests(unittest.TestCase):
    VERSION = "1.2.3.4"

    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "source"
        self.root.mkdir()
        self.out = self.base / "output"
        self.write("pyproject.toml", f'[project]\nversion = "{self.VERSION}"\n')
        self.write("src/nvlx/__init__.py", f'__version__ = "{self.VERSION}"\n')
        self.write("README.md", "release fixture\n")
        self.write("scripts/bootstrap.sh", "#!/bin/sh\nexit 0\n").chmod(0o755)
        root_patch = patch.object(release, "ROOT", self.root)
        root_patch.start()
        self.addCleanup(root_patch.stop)

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def assert_rejected_without_output(self, version=None):
        with self.assertRaises(release.ReleaseError):
            release.build(self.VERSION if version is None else version, self.out)
        self.assertFalse(self.out.exists())

    def test_archive_contents_and_manifest_match_package_version(self):
        archive, manifest = release.build(self.VERSION, self.out)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        self.assertEqual(manifest.read_text(), f"{digest}  {archive.name}\n")
        with tarfile.open(archive) as source:
            self.assertEqual(
                source.getnames(),
                [f"nvlx-{self.VERSION}/{name}" for name in (
                    "src/nvlx/__init__.py", "scripts/bootstrap.sh", "README.md", "pyproject.toml",
                )],
            )
            readme = source.extractfile(f"nvlx-{self.VERSION}/README.md")
            self.assertEqual(readme.read(), b"release fixture\n")

    def test_requested_version_mismatch_creates_no_output(self):
        self.assert_rejected_without_output("1.2.3.5")

    def test_package_version_mismatch_creates_no_output(self):
        self.write("src/nvlx/__init__.py", '__version__ = "9.9"\n')
        self.assert_rejected_without_output()

    def test_invalid_or_path_like_versions_create_no_output(self):
        for version in ("", "main", "../1.2", "/tmp/release", "1/2", "1\\2", "01.2", "1..2", "1.2\n", 123):
            with self.subTest(version=version):
                self.assert_rejected_without_output(version)

    def test_missing_invalid_or_dynamic_metadata_fails_closed(self):
        for content in ('[project]\n', '[project]\nversion = "main"\n', '[project]\nversion = [1, 2]\n', 'not toml'):
            with self.subTest(content=content):
                self.write("pyproject.toml", content)
                self.assert_rejected_without_output()

    def test_missing_or_ambiguous_package_version_fails_closed(self):
        for content in ('', '__version__ = object()\n', '__version__ = "1.2.3.4"\n__version__ = "1.2.3.4"\n', 'invalid python !'):
            with self.subTest(content=content):
                self.write("src/nvlx/__init__.py", content)
                self.assert_rejected_without_output()

    def test_package_version_is_read_without_executing_code(self):
        self.write("src/nvlx/__init__.py", f'__version__ = "{self.VERSION}"\nraise RuntimeError("must not execute")\n')
        archive, _ = release.build(self.VERSION, self.out)
        self.assertTrue(archive.is_file())

    def test_missing_metadata_creates_no_output(self):
        (self.root / "pyproject.toml").unlink()
        self.assert_rejected_without_output()

    def test_generated_metadata_and_bytecode_do_not_change_archive(self):
        archive_a, manifest_a = release.build(self.VERSION, self.out / "one")
        for name in ("src/nvlx.egg-info/PKG-INFO", "src/nvlx/__pycache__/cached.pyc", "src/nvlx/stale.pyc", "src/nvlx/stale.pyo", "docs/.DS_Store"):
            self.write(name, "generated data must not ship\n")
        archive_b, manifest_b = release.build(self.VERSION, self.out / "two")
        self.assertEqual(archive_a.read_bytes(), archive_b.read_bytes())
        self.assertEqual(manifest_a.read_bytes(), manifest_b.read_bytes())

    def test_timestamps_and_permission_variations_are_normalized(self):
        archive_a, _ = release.build(self.VERSION, self.out / "one")
        for path in tuple(release.files()):
            executable = bool(path.stat().st_mode & 0o111)
            path.chmod(0o700 if executable else 0o600)
            os.utime(path, (1_700_000_000, 1_700_000_000))
        archive_b, _ = release.build(self.VERSION, self.out / "two")
        self.assertEqual(archive_a.read_bytes(), archive_b.read_bytes())
        with tarfile.open(archive_b) as source:
            for member in source.getmembers():
                self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 0))
                self.assertEqual((member.uname, member.gname), ("root", "root"))
                self.assertEqual(member.mode, 0o755 if member.name.endswith(".sh") else 0o644)

    def test_file_symlink_is_rejected_before_output(self):
        external = self.base / "private.txt"
        external.write_text("must not ship", encoding="utf-8")
        (self.root / "src/nvlx/linked.py").symlink_to(external)
        self.assert_rejected_without_output()

    def test_directory_symlink_is_rejected_before_output(self):
        external = self.base / "private"
        external.mkdir()
        (external / "private.py").write_text("must not ship", encoding="utf-8")
        (self.root / "src/linked").symlink_to(external, target_is_directory=True)
        self.assert_rejected_without_output()

    def test_top_level_symlink_is_rejected_before_output(self):
        readme = self.root / "README.md"
        readme.unlink()
        readme.symlink_to(self.root / "pyproject.toml")
        self.assert_rejected_without_output()

    def test_output_inside_included_source_is_rejected(self):
        for name in ("src", "src/release", "docs/release", "scripts/output"):
            with self.subTest(name=name):
                out = self.root / name
                with self.assertRaisesRegex(release.ReleaseError, "outside"):
                    release.build(self.VERSION, out)
                self.assertFalse((out / f"nvlx-{self.VERSION}.tar.gz").exists())

    def test_symlinked_output_inside_source_is_rejected(self):
        self.out.symlink_to(self.root / "src", target_is_directory=True)
        with self.assertRaisesRegex(release.ReleaseError, "outside"):
            release.build(self.VERSION, self.out)
        self.assertFalse((self.root / "src/SHA256SUMS").exists())

    def test_cli_reports_invalid_versions_without_a_traceback(self):
        error = io.StringIO()
        with contextlib.redirect_stderr(error), self.assertRaises(SystemExit) as result:
            release.main(["../invalid", "--out", str(self.out)])
        self.assertEqual(result.exception.code, 2)
        self.assertIn("release version", error.getvalue())
        self.assertNotIn("Traceback", error.getvalue())
        self.assertFalse(self.out.exists())


if __name__ == "__main__":
    unittest.main()
