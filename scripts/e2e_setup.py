#!/usr/bin/env python3
"""Install Playwright browser dependencies."""

from __future__ import annotations

import sys

from shared import repo_root, run


def main() -> int:
    e2e_dir = repo_root() / "e2e"
    run(["npm", "install"], cwd=e2e_dir)
    run(["npx", "playwright", "install", "chromium"], cwd=e2e_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
