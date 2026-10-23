#!/usr/bin/env python3
"""Build a version-checked, deterministic source archive and SHA-256 manifest."""
from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import io
import re
import stat
import tarfile
import tomllib
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
INCLUDE = (
    "src", "config", "docs", "scripts", "tests", "README.md", "LICENSE",
    "pyproject.toml", "Makefile",
)
VERSION_PATTERN = re.compile(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))*\Z")


class ReleaseError(ValueError):
    """The source tree cannot safely produce the requested release."""


def validate_version(version: str) -> None:
    """Require the project's canonical numeric version format, never a path."""
    if not isinstance(version, str) or not VERSION_PATTERN.fullmatch(version):
        raise ReleaseError("release version must contain dot-separated canonical integers")


def project_version() -> str:
    """Read both version declarations without importing or executing the package."""
    try:
        metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        version = metadata["project"]["version"]
        validate_version(version)
        module = ast.parse((ROOT / "src/nvlx/__init__.py").read_text(encoding="utf-8"))
        declarations = [
            node.value
            for node in module.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "__version__"
                    for target in node.targets)
        ]
        if len(declarations) != 1 or ast.literal_eval(declarations[0]) != version:
            raise ReleaseError("pyproject.toml and nvlx.__version__ must match exactly")
    except (OSError, KeyError, TypeError, SyntaxError, ValueError) as exc:
        if isinstance(exc, ReleaseError):
            raise
        raise ReleaseError(f"cannot read consistent package versions: {exc}") from exc
    return version


def _excluded(path: Path) -> bool:
    return any(part == "__pycache__" or part.endswith(".egg-info") for part in path.parts) or (
        path.suffix in {".pyc", ".pyo"} or path.name == ".DS_Store"
    )


def files():
    """Collect regular source files, excluding generated metadata and bytecode."""
    for name in INCLUDE:
        base = ROOT / name
        if base.is_symlink():
            raise ReleaseError(f"release source must not be a symlink: {name}")
        if not base.exists():
            continue
        paths = sorted(base.rglob("*")) if base.is_dir() else [base]
        for path in paths:
            relative = path.relative_to(ROOT)
            if _excluded(relative):
                continue
            if path.is_symlink():
                raise ReleaseError(f"release source must not be a symlink: {relative}")
            if path.is_file():
                yield path
            elif not path.is_dir():
                raise ReleaseError(f"release source must be a regular file: {relative}")


def _validate_output_files(*paths: Path) -> None:
    """Never open an existing link, directory, or special file for output."""
    for path in paths:
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(mode):
            raise ReleaseError(f"release destination must be a regular file: {path.name}")


def build(version: str, out: Path) -> tuple[Path, Path]:
    validate_version(version)
    source_files = tuple(files())
    if version != project_version():
        raise ReleaseError("requested release version does not match the package version")
    out = Path(out).resolve()
    for name in INCLUDE:
        source = (ROOT / name).resolve()
        if out == source or source in out.parents:
            raise ReleaseError("release output must be outside the included source paths")

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for path in source_files:
            data = path.read_bytes()
            relative = path.relative_to(ROOT).as_posix()
            info = tarfile.TarInfo(f"nvlx-{version}/{relative}")
            info.size = len(data)
            info.mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
            info.uname = info.gname = "root"
            archive.addfile(info, io.BytesIO(data))

    # Finish validation and reading before creating output files.
    compressed = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=compressed, mtime=0, compresslevel=9) as gz:
        gz.write(raw.getvalue())
    data = compressed.getvalue()
    digest = hashlib.sha256(data).hexdigest()
    out.mkdir(parents=True, exist_ok=True)
    archive = out / f"nvlx-{version}.tar.gz"
    manifest = out / "SHA256SUMS"
    _validate_output_files(archive, manifest)
    # Stage both files on the destination filesystem before replacing either.
    # Each replacement is atomic; the two-file pair is not a transaction.
    with TemporaryDirectory(prefix=".nvlx-release-", dir=out) as temporary:
        staged_archive = Path(temporary) / archive.name
        staged_manifest = Path(temporary) / manifest.name
        staged_archive.write_bytes(data)
        staged_manifest.write_bytes(f"{digest}  {archive.name}\n".encode("utf-8"))
        _validate_output_files(archive, manifest)
        staged_archive.replace(archive)
        staged_manifest.replace(manifest)
    return archive, manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("--out", default="dist/repro")
    args = parser.parse_args(argv)
    try:
        archive, manifest = build(args.version, Path(args.out))
    except (ReleaseError, OSError) as exc:
        parser.error(str(exc))
    print(archive)
    print(manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
