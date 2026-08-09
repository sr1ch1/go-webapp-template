#!/usr/bin/env python3
"""cgo C-compiler wrapper that forwards everything to `zig cc`."""

from __future__ import annotations

import sys

from shared import run


def main() -> int:
    run(["zig", "cc", *sys.argv[1:]])
    return 0


if __name__ == "__main__":
    sys.exit(main())
