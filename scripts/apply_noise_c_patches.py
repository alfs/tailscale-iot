#!/usr/bin/env python3
"""Apply local patches to the noise-c git submodule.

This allows us to keep upstream noise-c untouched while layering ESP32
fixes that live inside this repository.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


def run_git(noise_dir: Path, *args: str) -> subprocess.CompletedProcess:
    cmd = ["git", "-C", str(noise_dir), *args]
    return subprocess.run(cmd, capture_output=True, text=True)


def patch_applied(noise_dir: Path, patch: Path) -> bool:
    # If the reverse patch applies cleanly, then the patch is already applied.
    result = run_git(noise_dir, "apply", "--reverse", "--check", str(patch))
    return result.returncode == 0


def apply_patch(noise_dir: Path, patch: Path, three_way: bool) -> None:
    args = ["apply", "--whitespace=nowarn"]
    if three_way:
        args.append("--3way")
    args.append(str(patch))
    result = run_git(noise_dir, *args)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        raise SystemExit(result.returncode)


def ensure_patches(noise_dir: Path, patch_dir: Path, check_only: bool, three_way: bool) -> None:
    if not patch_dir.exists():
        raise SystemExit(f"Patch directory {patch_dir} does not exist")

    patches = sorted(patch_dir.glob("*.patch"))
    if not patches:
        print(f"No patches found in {patch_dir}; nothing to do")
        return

    missing = []
    for patch in patches:
        if patch_applied(noise_dir, patch):
            print(f"Patch already applied: {patch.name}")
            continue
        if check_only:
            missing.append(patch)
            continue
        print(f"Applying patch: {patch.name}")
        apply_patch(noise_dir, patch, three_way)

    if missing:
        names = ", ".join(p.name for p in missing)
        raise SystemExit(f"Patches not applied: {names}")


def parse_args() -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--noise-dir",
        type=Path,
        default=repo_root / "external" / "required" / "noise-c",
        help="Path to the noise-c git checkout",
    )
    parser.add_argument(
        "--patch-dir",
        type=Path,
        default=repo_root / "patches" / "noise-c",
        help="Directory containing *.patch files to apply",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Only check whether patches are applied without modifying files",
    )
    parser.add_argument(
        "--no-3way",
        action="store_true",
        help="Disable git apply --3way",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not shutil.which("git"):
        raise SystemExit("git executable not found in PATH")
    noise_dir = args.noise_dir.resolve()
    if not noise_dir.exists():
        raise SystemExit(f"noise-c directory not found: {noise_dir}")
    ensure_patches(noise_dir, args.patch_dir.resolve(), args.check, not args.no_3way)


if __name__ == "__main__":
    main()
