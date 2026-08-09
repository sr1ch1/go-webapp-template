#!/usr/bin/env python3
"""Run browser-based end-to-end tests."""

from __future__ import annotations

import sys

from shared import repo_root, run


def main() -> int:
    run(["npm", "test"], cwd=repo_root() / "e2e")
    return 0


if __name__ == "__main__":
    sys.exit(main())
