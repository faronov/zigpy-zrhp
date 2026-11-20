#!/usr/bin/env python3
"""Compare (or update) tests/vectors with the ZRHP vectors of faronov/zigbee-rs.

scripts/sync_vectors.py --check            # CI: fail if the copies drifted
scripts/sync_vectors.py --update [--ref R]  # refresh the copies
scripts/sync_vectors.py --check --source DIR  # compare with a local checkout
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import urllib.request

FILES = (
    "arq_scenarios.json",
    "cobs.json",
    "crc32c.json",
    "ezsp_hashed_tclk.json",
    "link_frames.json",
    "messages.json",
    "ocb_roundtrip.json",
    "ocb_z2m_import.json",
)
UPSTREAM = "https://raw.githubusercontent.com/faronov/zigbee-rs/{ref}/docs/book/src/advanced/host-protocol-vectors/{name}"
HERE = pathlib.Path(__file__).resolve().parent.parent / "tests" / "vectors"


def fetch(name: str, ref: str, source: pathlib.Path | None) -> bytes:
    if source is not None:
        return (source / name).read_bytes()
    with urllib.request.urlopen(UPSTREAM.format(ref=ref, name=name), timeout=30) as rsp:
        return rsp.read()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--ref", default="master")
    p.add_argument("--source", type=pathlib.Path)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--update", action="store_true")
    args = p.parse_args()
    drift = []
    for name in FILES:
        upstream = fetch(name, args.ref, args.source)
        local = HERE / name
        if args.update:
            local.write_bytes(upstream)
            continue
        if json.loads(upstream) != json.loads(local.read_bytes()):
            drift.append(name)
    if drift:
        print("vectors differ from upstream:", ", ".join(drift))
        print("run scripts/sync_vectors.py --update and re-run the tests")
        return 1
    print("vectors up to date" if args.check else "vectors updated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
