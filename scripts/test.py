#!/usr/bin/env python3
"""Run the Go test suite with the race detector."""

from __future__ import annotations

import sys

from shared import require_commands, run


def main() -> int:
    require_commands("go")
    run(["go", "test", "-race", "./..."])
    return 0


if __name__ == "__main__":
    sys.exit(main())
