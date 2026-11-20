# zigpy-zrhp

A [zigpy](https://github.com/zigpy/zigpy) radio library for
[zigbee-rs](https://github.com/faronov/zigbee-rs) network co-processors
(NCPs) that speak **ZRHP**, the zigbee-rs Host Protocol
([specification](https://github.com/faronov/zigbee-rs/blob/master/docs/book/src/advanced/host-protocol.md)).
The NCP runs the complete Zigbee PRO coordinator, Trust Center and Green
Power combo (proxy + sink); this library connects it to zigpy (and so to
Home Assistant ZHA). Radio type: `zrhp`.

> Status: pure-Python implementation of ZRHP v1, tested byte-exact against
> all shared vectors, against a Python NCP simulator and against the Rust NCP
> code (`ncp_sim`). Hardware validation on the ESP32-H2 NCP is in progress.
> Maintained in the `faronov` forks; there is no upstream zigpy integration.

## Features

| Area | What the library does |
|---|---|
| Transports | USB-Serial-JTAG (ESP32-H2/C6 native USB) and UART. UART defaults to 921 600 baud; if no session comes up it retries at 460 800 without flow control (the Thread BR board fallback). DTR/RTS are always changed together; a DTR/RTS hard reset is the last resume step. |
| Link layer | COBS + CRC-32C framing, selective-repeat ARQ with SACK and immediate NAK, per-endpoint ordering and credits, keepalive, session handshake with cookies and epoch. A line-by-line port of `zigbee_zrhp::link`, checked against `arq_scenarios.json`. |
| Messages | Every v1 command, event and record (spec 7-9) with typed codecs. Many requests in flight; `RETRY` after a link resync (6.5). |
| zigpy | `connect`, `start_network`, `load_network_info`, `write_network_info`, `reset_network_info`, `send_packet` (BUSY back-off, APS confirms, source routes, extended timeout), `packet_received`, `permit`, `permit_ncp`, `permit_with_link_key`, `energy_scan`, `add_endpoint`, `force_remove`, channel change, TX power, group membership, `_watchdog_feed` with counters. ZDO requests to the coordinator are answered on the host (no loopback). |
| Seamless resume | An NCP reboot or a link loss is hidden from zigpy when the NCP state reconciles (IEEE, PAN ID, EPID, channel, update ID, key sequence, `table_epoch`): requests wait, then endpoints, groups, TC policy, GP sink, permit-join and GP windows and the key-export lock are replayed. `connection_lost` only when it cannot be reconciled. |
| Host store | Sidecar SQLite `zigbee_zrhp.db` next to `zigbee.db` (WAL, `synchronous=FULL`): link keys from `TBL_WRITEBACK`, `TBL_LOOKUP` answers, the frame-counter checkpoint log whose floors go into `NWK_INIT`, table epoch, GP shadow. Standalone mode is the default; paging is decided by the NCP. |
| Backups | zigpy network backups map to Open Coordinator Backup records (`NODE`, `NETWORK`, keys, `DEVICE`, `RS_PARAMS`, GP tables) with `stack_specific.zigbee_rs`. Restores use `nwk_margin = 0`, `aps_margin = 10 000` (2^20 when the APS counter is unknown). EZSP hashed TCLK and other stacks' `stack_specific` keys pass through. Optional lock of key export after each backup. |
| Green Power | The NCP sink is authoritative; zigpy is its shadow: `EVT_GP_FRAME` feeds `gp_packet_received`, zigpy's own sink transmissions are swallowed, unpair becomes `GP_SINK_REMOVE`, GPDs are reconciled with the NCP Sink Table at start and resume. Security level 0x00 (zigpy-compatible). |

### The Green Power hook

With the `faronov/zigpy` fork (branch `zrhp-hooks`), zigpy's
`GreenPowerManager` delegates commissioning and unpairing to the radio
(`ControllerApplication.gp_radio_sink`) and transmits nothing itself. The
library works with stock zigpy too, by swallowing those transmissions.

```sh
pip install "zigpy-zrhp[gp-hook]"   # or: pip install zigpy-zrhp
```

## Configuration

```yaml
zha:
  zigpy_config:
    zrhp_config:
      resume_budget: 20               # seconds requests wait for an NCP to come back
      lock_key_export_after_backup: false
      gp_sink: ncp                    # or "host": zigpy is the GP sink
      gp_security_level: 0
```

The device is configured as usual (`path`, `baudrate` default 921 600,
`flow_control` default none). Other options: `baudrate_fallback`,
`sidecar_path`, `hard_reset_on_resume_failure`, `connect_timeout`,
`confirm_timeout`, `confirm_timeout_extended`, `tc_policy`,
`manufacturer_code`.

On the Espressif Thread Border Router board the Mac sees the H2 through the
S3 bridge (`/dev/cu.usbmodem…01`, CDC 0); the bridge maps DTR/RTS to the H2's
EN/BOOT like esptool, and opening the port never resets it.

## Diagnostics CLI

```sh
zigpy-zrhp -p /dev/cu.usbmodem7CDFA1FE67F01 info
zigpy-zrhp -p PORT counters [--reset]
zigpy-zrhp -p PORT echo --count 1000 --size 64 --depth 16
zigpy-zrhp -p PORT neighbors | children | routes | gp-sink-table
zigpy-zrhp -p PORT backup backup.json
zigpy-zrhp -p PORT restore backup.json [--allow-ieee-change] [--force]
zigpy-zrhp -p PORT form --channel 17 --pan-id 0x1C06
zigpy-zrhp -p PORT permit 60 --ncp-only --listen
zigpy-zrhp -p PORT listen --seconds 60 --log-level 3
zigpy-zrhp -p PORT reset [--mode reboot|bootloader|factory] [--hard]
zigpy-zrhp sim        # a simulated NCP on a pseudo-terminal
zigpy-zrhp -p PORT app --pan-id 0x1C06 --channel 17 --form --permit 120 --run 300
                      # zigpy itself on the NCP (no Home Assistant), printing joins
```

## Development

```sh
python -m venv .venv && .venv/bin/pip install -e ".[testing]"
.venv/bin/pytest
scripts/sync_vectors.py --check      # shared vectors vs. faronov/zigbee-rs
```

Tests:

* `test_vectors.py`, `test_ocb_vectors.py`, `test_arq.py`: every vector file,
  byte-exact (CRC, COBS, link frames, all messages, ARQ traces, OCB
  round trip and Z2M import, install code and EZSP hashed-TCLK candidates).
* `test_link.py`: link conformance and seeded noise (bit errors, drops,
  inserted `0x00`, duplicated chunks), HOL blocking, wrap, REJECT, resets.
* `test_api.py`, `test_application.py`, `test_resume.py`, `test_backup.py`,
  `test_gp.py`: the library against the Python NCP simulator
  (`zigpy_zrhp.sim`), with simulated devices that answer zigpy's interview.
* `test_rust_ncp.py`: against the Rust NCP (`examples/ncp_sim.rs` on the
  `zrhp-ncp-sim` branch of zigbee-rs) when `ZRHP_NCP_SIM` points to it.

## License

GPL-3.0, like zigpy. The vectors in `tests/vectors` come from zigbee-rs
(MIT OR Apache-2.0).
