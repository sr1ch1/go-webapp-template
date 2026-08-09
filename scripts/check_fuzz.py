#!/usr/bin/env python3
"""Run fuzz targets with a bounded time budget."""

from __future__ import annotations

import sys

from shared import require_commands, run

FUZZ_TARGETS = [
    "FuzzVerifyMalformedToken",
    "FuzzVerifySignatureRS256",
]


def main() -> int:
    require_commands("go")
    for target in FUZZ_TARGETS:
        run(["go", "test", f"-fuzz={target}", "-fuzztime=60s", "./internal/auth"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
