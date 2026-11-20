# ZRHP vectors

Copies of the shared golden vectors of the ZRHP specification
(`docs/book/src/advanced/host-protocol-vectors/` in
[faronov/zigbee-rs](https://github.com/faronov/zigbee-rs), MIT OR
Apache-2.0), generated there by `generate.py`. The tests load these files
directly; `scripts/sync_vectors.py --check` (run in CI) fails when they drift
from upstream `master`.
