#!/usr/bin/env python3
"""Run the app with live reload via air."""

from __future__ import annotations

import sys

from shared import require_commands, run


def main() -> int:
    require_commands("air")
    run(["air"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
