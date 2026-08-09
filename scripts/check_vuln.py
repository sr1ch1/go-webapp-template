#!/usr/bin/env python3
"""Scan Go dependencies and code for known vulnerabilities."""

from __future__ import annotations

import sys

from shared import require_commands, run


def main() -> int:
    require_commands("govulncheck")
    run(["govulncheck", "./..."])
    return 0


if __name__ == "__main__":
    sys.exit(main())
