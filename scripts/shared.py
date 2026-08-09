"""Shared helpers for the Python-based mise task scripts."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


def repo_root() -> Path:
    """Return the repository root directory."""
    return Path(__file__).resolve().parent.parent


def run(
    cmd: list[str],
    *,
    cwd: Path | str | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
    capture_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run a command, streaming output by default.

    Exits cleanly on failure or if the command is not found.
    """
    if isinstance(cwd, Path):
        cwd = str(cwd)
    try:
        return subprocess.run(
            cmd,
            cwd=cwd,
            env=env,
            check=check,
            capture_output=capture_output,
            text=True,
        )
    except FileNotFoundError:
        print(f"command not found: {cmd[0]}", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        if capture_output and e.stdout:
            print(e.stdout, end="")
        if capture_output and e.stderr:
            print(e.stderr, end="", file=sys.stderr)
        sys.exit(e.returncode)


def require_commands(*names: str) -> None:
    """Exit if any of the required commands are missing from PATH."""
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        print(
            f"required commands not found: {', '.join(missing)}",
            file=sys.stderr,
        )
        sys.exit(1)


def ensure_dir(path: Path | str) -> None:
    """Create a directory and its parents if they do not exist."""
    Path(path).mkdir(parents=True, exist_ok=True)


def binary_path(stem: str) -> str:
    """Return an executable path with the correct suffix for the platform."""
    suffix = ".exe" if platform.system() == "Windows" else ""
    return f"{stem}{suffix}"


def has_system_compiler() -> bool:
    """Return True if a gcc/clang-compatible compiler is on PATH."""
    return any(shutil.which(name) for name in ("cc", "clang", "gcc"))
