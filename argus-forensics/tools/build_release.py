"""Produce a portable, verifiable ARGUS release.

A forensic workstation is often air-gapped and locked down: no pip, no network,
sometimes no ability to install anything at all. So a release is a single
folder that runs from wherever it is unzipped, carrying its own manifest so the
build can be identified and its integrity checked on the bench.

Produces:

    dist/argus-<version>/            the portable tree
    dist/argus-<version>.zip         the same tree, zipped
    dist/argus-<version>.sha256      digest of the zip, for transfer checking

Run:  python3 tools/build_release.py
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import shutil
import stat
import sys
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from argus import __version__
from argus.core.selfcheck import build_manifest

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Shipped as-is. Tests and samples are included deliberately: an examiner who
# has to justify the tool should be able to run its test suite on the same
# machine, and a validation harness nobody can execute is not evidence of
# anything.
INCLUDE = ["argus", "tests", "samples", "tools", "docs",
           "README.md", "pyproject.toml",
           "ARGUS.bat", "ARGUS.command", "ARGUS.sh", "argus_app.py",
           "Start ARGUS.vbs", "Create Desktop Shortcut.bat"]

EXCLUDE_PARTS = {"__pycache__", ".git", ".pytest_cache", ".mypy_cache",
                 "dist", "build", ".venv", "venv", "node_modules"}


def _writable(path: pathlib.Path) -> None:
    """Make a staged entry writable.

    `copy2` preserves the source mode. Where the checkout is read-only — a
    network share, a mounted image, a CI cache — every staged file inherits
    that, and the release folder then cannot be cleaned or rebuilt without
    fighting permissions. An archive should not carry the idiosyncrasies of the
    machine that built it.

    Directories matter as much as files: unlinking a file needs the write bit on
    its *parent*, so chmod-ing only files still leaves an undeletable tree.
    """
    try:
        path.chmod(path.stat().st_mode | stat.S_IWUSR)
    except OSError:
        pass


def _copy(src: pathlib.Path, dst: pathlib.Path) -> int:
    """Copy a file or tree, skipping caches. Returns the file count."""
    if src.is_file():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        _writable(dst)
        return 1
    count = 0
    for path in sorted(src.rglob("*")):
        if any(part in EXCLUDE_PARTS for part in path.parts):
            continue
        if not path.is_file():
            continue
        target = dst / path.relative_to(src)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        _writable(target)
        count += 1
    return count


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "dist"))
    ap.add_argument("--no-zip", action="store_true")
    args = ap.parse_args()

    dist = pathlib.Path(args.out)
    name = f"argus-{__version__}"
    staging = dist / name
    if staging.exists():
        # A previous build may have left read-only entries behind.
        _writable(staging)
        for path in sorted(staging.rglob("*"), reverse=True):
            _writable(path)
        shutil.rmtree(staging)
    staging.mkdir(parents=True)

    total = 0
    for item in INCLUDE:
        src = ROOT / item
        if not src.exists():
            print(f"  skip (absent): {item}")
            continue
        total += _copy(src, staging / item)
    print(f"  staged {total} files into {staging}")

    # The manifest must be built from the staged tree, not the working tree:
    # it has to describe exactly what ships, including any file the copy step
    # dropped. Building it from the source tree would produce a manifest that
    # fails verification on the very first run after install.
    manifest = build_manifest(staging / "argus")
    manifest_path = staging / "argus" / "MANIFEST.json"
    manifest_path.write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    print(f"  manifest: {manifest['file_count']} files, "
          f"build {manifest['installation_id'][:16]}")

    if args.no_zip:
        return 0

    archive = dist / f"{name}.zip"
    if archive.exists():
        archive.unlink()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(staging.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(dist).as_posix())

    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (dist / f"{name}.sha256").write_text(
        f"{digest}  {archive.name}\n", encoding="utf-8")

    size_mb = archive.stat().st_size / (1024 * 1024)
    print(f"  archive : {archive}  ({size_mb:.1f} MB)")
    print(f"  sha256  : {digest}")
    print()
    print("  Verify after transfer:")
    print(f"    sha256sum -c {name}.sha256")
    print("  Then, on the workstation:")
    print(f"    unzip {name}.zip && cd {name} && python3 -m argus.cli selfcheck")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
