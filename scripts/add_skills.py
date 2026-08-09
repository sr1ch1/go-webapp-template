#!/usr/bin/env python3
"""Install commonly used AI skills."""

from __future__ import annotations

import sys

from shared import run


def main() -> int:
    run(["npx", "skills", "add", "mattpocock/skills"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
