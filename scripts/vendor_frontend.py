#!/usr/bin/env python3
"""Download pinned frontend assets and verify SHA-256 checksums."""

from __future__ import annotations

import base64
import hashlib
import sys
import urllib.request
from pathlib import Path

from shared import ensure_dir, repo_root

ASSETS = [
    (
        "https://cdn.jsdelivr.net/npm/htmx.org@2.0.10/dist/htmx.min.js",
        "htmx.min.js",
        "71ea67185bfa8c98c39d31717c6fce5d852370fcdfd129db4543774d3145c0de",
    ),
    (
        "https://cdn.jsdelivr.net/npm/@alpinejs/csp@3.15.12/dist/cdn.min.js",
        "alpine-csp.min.js",
        "566167134bb2347110904e2ced6e816d2e8d837200c158f98b72372b3bb0b9a6",
    ),
]


def fetch(url: str, file_path: Path, expected_sha256: str) -> None:
    print(f"fetching {file_path.name} ...")
    data = urllib.request.urlopen(url, timeout=30).read()

    actual_sha256 = hashlib.sha256(data).hexdigest()
    if actual_sha256 != expected_sha256:
        print(
            f"checksum mismatch for {file_path.name}: got {actual_sha256}, want {expected_sha256}",
            file=sys.stderr,
        )
        sys.exit(1)

    file_path.write_bytes(data)

    sri = "sha384-" + base64.b64encode(hashlib.sha384(data).digest()).decode("ascii")
    print(f"ok: {file_path.name} ({actual_sha256})")
    print(f"  SRI: {sri}")


def main() -> int:
    vendor_dir = repo_root() / "web" / "static" / "vendor"
    ensure_dir(vendor_dir)

    for url, filename, expected_sha256 in ASSETS:
        fetch(url, vendor_dir / filename, expected_sha256)

    return 0


if __name__ == "__main__":
    sys.exit(main())
