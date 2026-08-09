#!/usr/bin/env python3
"""Build the application binary for the current platform."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from shared import binary_path, ensure_dir, has_system_compiler, run


def git_output(args: list[str]) -> str | None:
    try:
        return subprocess.check_output(["git", *args], text=True).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def build_metadata() -> tuple[str, str, str]:
    version = git_output(["describe", "--tags", "--always", "--dirty"]) or "dev"
    commit = git_output(["rev-parse", "--short", "HEAD"]) or "unknown"
    build_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return version, commit, build_time


def main() -> int:
    ensure_dir("bin")

    env = os.environ.copy()
    env["CGO_ENABLED"] = "1"

    if not has_system_compiler():
        if shutil.which("zig") is None:
            print(
                "No C compiler found. Install clang/gcc, or install zig via mise.",
                file=sys.stderr,
            )
            return 1

        if platform.system() == "Windows":
            # Go on Windows needs a single executable for CC. Forward through a
            # Python wrapper so we can still invoke `zig cc`.
            wrapper = (Path(__file__).resolve().parent / "cc_zig.py").as_posix()
            env["CC"] = f"{sys.executable} {wrapper}"
        else:
            env["CC"] = "zig cc"

    version, commit, build_time = build_metadata()
    ldflags = (
        f"-X github.com/sandrorichi/webapp-template/internal/version.Version={version} "
        f"-X github.com/sandrorichi/webapp-template/internal/version.Commit={commit} "
        f"-X github.com/sandrorichi/webapp-template/internal/version.BuildTime={build_time}"
    )

    output = binary_path("bin/app")
    run(["go", "build", "-ldflags", ldflags, "-o", output, "./cmd/app"], env=env)
    print(f"built {output} ({platform.system().lower()}/{platform.machine()}) {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
