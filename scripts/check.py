#!/usr/bin/env python3
"""Run the full check suite."""

from __future__ import annotations

import sys

from shared import require_commands, run


def main() -> int:
    require_commands("gofmt", "go", "golangci-lint", "govulncheck")

    result = run(["gofmt", "-l", "."], capture_output=True, check=False)
    if result.stdout:
        print("gofmt needed:")
        print(result.stdout, end="")
        return 1

    run(["golangci-lint", "run", "./..."])
    run(["go", "vet", "./..."])
    run(["govulncheck", "./..."])
    run(["go", "test", "-race", "-coverprofile=coverage.txt", "./..."])

    return 0


if __name__ == "__main__":
    sys.exit(main())
