"""``zigpy-zrhp``: diagnostics for zigbee-rs NCPs speaking ZRHP.

Examples::

    zigpy-zrhp -p /dev/cu.usbmodem1101 info
    zigpy-zrhp -p /dev/ttyUSB0 -b 921600 counters
    zigpy-zrhp -p /dev/ttyACM0 echo --count 1000 --size 64 --depth 16
    zigpy-zrhp -p /dev/ttyACM0 backup backup.json
    zigpy-zrhp -p /dev/ttyACM0 listen --seconds 60
    zigpy-zrhp sim          # a simulated NCP on a pseudo-terminal
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import statistics
import sys
import time
from typing import Any

from .. import __version__, messages as m
from ..api import ZrhpApi, ZrhpError
from ..link import COUNTER_NAMES
from ..ocb import ieee_text, ocb_to_records, records_to_ocb, restore_margins
from ..records import decode_records, encode_record
from ..transport import ByteTransport, SerialTransport
from ..types import FACTORY_RESET_CONFIRM, LOCK_CONFIRM, NcpCaps, Status

LOGGER = logging.getLogger("zigpy_zrhp.cli")


def _transport(args) -> ByteTransport:
    flow = None if args.flow_control == "none" else args.flow_control
    return SerialTransport(args.port, args.baudrate, flow)


async def _connect(args) -> ZrhpApi:
    api = ZrhpApi(
        lambda: _transport(args),
        name=f"zigpy-zrhp-cli/{__version__}",
        handshake_timeout=args.timeout,
    )
    await api.connect()
    return api


def _out(args, data: dict[str, Any]) -> None:
    if args.json:
        print(json.dumps(data, indent=2, default=_json_default))
        return
    for k, v in data.items():
        print(f"{k:28} {v}")


def _json_default(o: Any) -> Any:
    if isinstance(o, bytes):
        return o.hex()
    if hasattr(o, "as_dict"):
        return o.as_dict()
    return str(o)


async def cmd_info(api: ZrhpApi, args) -> None:
    s = api.session
    _, info = await api.request(m.SysGetInfoReq())
    _, status = await api.request(m.SysGetStatusReq())
    _, net = await api.request(m.NwkGetInfoReq())
    fc = None
    try:
        _, fc = await api.request(m.SecGetFrameCountersReq())
    except ZrhpError:
        pass
    caps = [c.name for c in NcpCaps if s.negotiate.ncp_caps & c]
    data = {
        "firmware": s.fw_version,
        "build_id": s.negotiate.build_id.hex(),
        "chip": s.negotiate.chip,
        "protocol": f"{s.negotiate.major}.{s.negotiate.minor}",
        "capabilities": ", ".join(caps),
        "capacities": {c.id: c.value for c in s.negotiate.capacities},
        "ncp_cookie": f"0x{s.ncp_cookie:08X}",
        "reset_reason": s.ready.reset_reason,
        "table_epoch": s.ready.table_epoch,
        "ieee_factory": ieee_text(info.ieee_factory),
        "ieee_active": ieee_text(info.ieee_active),
        "board": info.board.decode(errors="replace"),
        "product": info.product.decode(errors="replace"),
        "transport": "USB-Serial-JTAG"
        if info.transport == 1
        else f"UART {info.uart_baud} flow={info.uart_flow}",
        "flash_size": info.flash_size,
        "network_state": net.state,
        "pan_id": f"0x{net.pan_id:04X}",
        "ext_pan_id": ieee_text(net.ext_pan_id),
        "channel": net.channel,
        "nwk_update_id": net.nwk_update_id,
        "key_seq": net.key_seq,
        "tx_power": net.tx_power,
        "uptime_s": status.uptime_s,
        "status_flags": f"0x{status.flags:02X}",
    }
    if fc is not None:
        data["nwk_counter"] = f"{fc.nwk_current} (limit {fc.nwk_limit})"
        data["aps_counter"] = f"{fc.aps_current} (limit {fc.aps_limit})"
    _out(args, data)


async def cmd_counters(api: ZrhpApi, args) -> None:
    if args.reset:
        await api.request(m.DiagResetCountersReq(group_mask=0xFF))
    _, rsp = await api.request(m.DiagGetCountersReq(group_mask=0xFF))
    data = {COUNTER_NAMES.get(c.id, f"0x{c.id:04X}"): c.value for c in rsp.counters}
    if api.driver is not None:
        data.update({f"host.{k}": v for k, v in api.driver.counters().items()})
    _out(args, data)


async def cmd_echo(api: ZrhpApi, args) -> None:
    sem = asyncio.Semaphore(args.depth)
    rtts: list[float] = []
    errors = 0

    async def one(i: int) -> None:
        nonlocal errors
        payload = bytes((i + j) & 0xFF for j in range(args.size))
        async with sem:
            t0 = time.perf_counter()
            try:
                _, rsp = await api.request(m.SysEchoReq(data=payload), timeout=10)
            except ZrhpError:
                errors += 1
                return
            if rsp.data != payload:
                errors += 1
            rtts.append((time.perf_counter() - t0) * 1000)

    start = time.perf_counter()
    await asyncio.gather(*(one(i) for i in range(args.count)))
    elapsed = time.perf_counter() - start
    data = {
        "echoes": len(rtts),
        "errors": errors,
        "elapsed_s": round(elapsed, 3),
        "throughput_kib_s": round(2 * args.size * len(rtts) / elapsed / 1024, 1) if elapsed else 0,
    }
    if rtts:
        q = statistics.quantiles(rtts, n=100) if len(rtts) > 1 else [rtts[0]] * 99
        data.update(
            rtt_ms_p50=round(q[49], 2), rtt_ms_p99=round(q[98], 2), rtt_ms_max=round(max(rtts), 2)
        )
    _out(args, data)
    if errors:
        raise SystemExit(1)


async def _table(api: ZrhpApi, req_cls, args) -> None:
    start = 0
    rows = []
    while True:
        _, rsp = await api.request(req_cls(start=start))
        rows += rsp.entries
        start += len(rsp.entries)
        if not rsp.entries or start >= rsp.total:
            break
    for r in rows:
        d = r.as_dict()
        if "ieee" in d:
            d["ieee"] = ieee_text(d["ieee"])
        print(json.dumps(d, default=_json_default))


async def cmd_backup(api: ZrhpApi, args) -> None:
    _, begin = await api.request(m.BkpExportBeginReq(flags=0x07))
    stream = bytearray()
    try:
        while True:
            _, rsp = await api.request(m.BkpExportReadReq(txn=begin.txn, max_bytes=600))
            stream += rsp.records
            if not rsp.more:
                break
    finally:
        await api.request(
            m.BkpExportEndReq(txn=begin.txn), allow=(Status.SUCCESS, Status.NOT_FOUND)
        )
    records = decode_records(bytes(stream))
    ocb = records_to_ocb(
        records,
        source=f"zigpy-zrhp-cli@{__version__}",
        creation_time=time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
    )
    with open(args.file, "w") as f:
        json.dump(ocb, f, indent=2)
    print(f"{len(records)} records, {len(ocb['devices'])} devices -> {args.file}")


async def cmd_restore(api: ZrhpApi, args) -> None:
    with open(args.file) as f:
        ocb = json.load(f)
    records = ocb_to_records(ocb, node_flags=0x01 if args.allow_ieee_change else 0)
    nwk_margin, aps_margin = restore_margins(ocb, nwk_margin=args.nwk_margin)
    _, net = await api.request(m.NwkGetInfoReq())
    if net.state == 2:
        if not args.force:
            raise SystemExit(
                "The NCP runs a network; pass --force to wipe it (NWK_LEAVE_RESET) first"
            )
        await api.request(m.NwkLeaveResetReq(flags=0x03), timeout=15)
    _, begin = await api.request(
        m.BkpRestoreBeginReq(
            flags=0x01 if args.allow_ieee_change else 0,
            nwk_margin=nwk_margin,
            aps_margin=aps_margin,
            expected_records=len(records),
        )
    )
    tlvs = [encode_record(r) for r in records]
    chunk: list[bytes] = []
    for tlv in [*tlvs, None]:
        if tlv is None or (
            chunk
            and (len(chunk) >= begin.max_records_per_put or sum(map(len, chunk)) + len(tlv) > 600)
        ):
            if chunk:
                await api.request(m.BkpRestorePutReq(txn=begin.txn, records=b"".join(chunk)))
            chunk = []
        if tlv is not None:
            chunk.append(tlv)
    _, commit = await api.request(m.BkpRestoreCommitReq(txn=begin.txn), timeout=30)
    _out(args, commit.as_dict())


async def cmd_form(api: ZrhpApi, args) -> None:
    mask = 0
    for ch in args.channel:
        mask |= 1 << ch
    loop = asyncio.get_running_loop()
    up: asyncio.Future = loop.create_future()

    def on_event(msg, body) -> None:
        if msg.msg_id == m.Id.EVT_NETWORK_STATE and not up.done():
            up.set_result(body)

    api.add_event_handler(on_event)
    await api.request(
        m.NwkFormReq(
            channel_mask=mask,
            pan_id=args.pan_id,
            ext_pan_id=bytes(8),
            network_key=bytes(16),
            key_seq=0,
            nwk_update_id=0,
            tx_power=args.tx_power,
            nwk_manager=0,
        )
    )
    evt = await asyncio.wait_for(up, 30)
    print(f"network state {evt.state} (zb_status 0x{evt.zb_status:02X})")
    await cmd_info(api, args)


async def cmd_init(api: ZrhpApi, args) -> None:
    await api.request(m.NwkInitReq(nwk_fc_floor=0, aps_fc_floor=0), timeout=15)
    await asyncio.sleep(1)
    await cmd_info(api, args)


async def cmd_permit(api: ZrhpApi, args) -> None:
    target = 0x0000 if args.ncp_only else 0xFFFC
    await api.request(
        m.NwkPermitJoinReq(duration_s=args.seconds, target=target, flags=1), timeout=10
    )
    print(f"permit join {args.seconds}s on 0x{target:04X}")
    if args.listen:
        await _listen(api, args.seconds + 5)


async def _listen(api: ZrhpApi, seconds: float) -> None:
    def on_event(msg, body) -> None:
        if msg.msg_id == m.Id.EVT_LOG_RECORD:
            print(f"[log {body.level}] {body.text.decode(errors='replace')}")
            return
        print(f"{m.name_of(msg.msg_id)} {body!r}")

    api.add_event_handler(on_event)
    await asyncio.sleep(seconds)


async def cmd_listen(api: ZrhpApi, args) -> None:
    if args.log_level is not None:
        await api.request(m.LogConfigReq(level=args.log_level, module_mask=0xFFFFFFFF))
    await _listen(api, args.seconds)


async def cmd_reset(api: ZrhpApi, args) -> None:
    if args.hard:
        await api.hard_reset()
        print("DTR/RTS hard reset sent")
        return
    mode = {"reboot": 0, "bootloader": 1, "factory": 2}[args.mode]
    confirm = FACTORY_RESET_CONFIRM if mode == 2 else 0
    await api.request(m.SysResetReq(mode=mode, confirm=confirm))
    print(f"SYS_RESET {args.mode} accepted")


async def cmd_lock(api: ZrhpApi, args) -> None:
    await api.request(m.SecLockKeyExportReq(confirm=LOCK_CONFIRM))
    print("key export locked until the next NCP reboot")


async def cmd_gp(api: ZrhpApi, args) -> None:
    start = 0
    while True:
        _, rsp = await api.request(m.GpSinkTableReadReq(start=start))
        for r in rsp.records:
            print(repr(r))
        start += len(rsp.records)
        if not rsp.records or start >= rsp.total:
            break


def run_app(args) -> None:
    """Run a zigpy ControllerApplication on the NCP (no Home Assistant)."""
    import pathlib

    import zigpy.config as zconf

    from ..zigbee.application import ControllerApplication

    db = pathlib.Path(args.database).expanduser()
    db.parent.mkdir(parents=True, exist_ok=True)
    nwk: dict[str, Any] = {}
    if args.pan_id is not None:
        nwk[zconf.CONF_NWK_PAN_ID] = args.pan_id
    if args.channel is not None:
        nwk[zconf.CONF_NWK_CHANNEL] = args.channel
        nwk[zconf.CONF_NWK_CHANNELS] = [args.channel]
    config = {
        zconf.CONF_DEVICE: {
            zconf.CONF_DEVICE_PATH: args.port,
            zconf.CONF_DEVICE_BAUDRATE: args.baudrate,
            zconf.CONF_DEVICE_FLOW_CONTROL: None
            if args.flow_control == "none"
            else args.flow_control,
        },
        zconf.CONF_DATABASE: str(db),
        zconf.CONF_NWK: nwk,
        zconf.CONF_OTA: {zconf.CONF_OTA_ENABLED: False},
        zconf.CONF_TOPO_SCAN_ENABLED: False,
    }

    class Listener:
        def device_joined(self, device) -> None:
            print(f"JOINED   {device.ieee} nwk=0x{device.nwk:04X}", flush=True)

        def device_initialized(self, device) -> None:
            print(f"READY    {device.ieee} {device.manufacturer!r} {device.model!r}", flush=True)

        def device_left(self, device) -> None:
            print(f"LEFT     {device.ieee}", flush=True)

        def handle_message(self, device, profile, cluster, src_ep, dst_ep, message) -> None:
            print(f"RX       {device.ieee} ep{src_ep} 0x{cluster:04X} {message.hex()}", flush=True)

        def connection_lost(self, exc) -> None:
            print(f"LOST     {exc!r}", flush=True)

    async def main() -> None:
        app = await ControllerApplication.new(config, auto_form=args.form)
        app.add_listener(Listener())
        ni, node = app.state.network_info, app.state.node_info
        print(
            f"NETWORK  pan=0x{ni.pan_id:04X} channel={ni.channel} epid={ni.extended_pan_id} "
            f"ieee={node.ieee} devices={len(app.devices) - 1}",
            flush=True,
        )
        try:
            if args.permit:
                if args.ncp_only:
                    await app.permit_ncp(args.permit)
                else:
                    await app.permit(args.permit)
                print(f"PERMIT   {args.permit}s", flush=True)
            if args.backup:
                backup = await app.backups.create_backup(load_devices=True)
                with open(args.backup, "w") as f:
                    json.dump(backup.as_open_coordinator_json(), f, indent=2)
                print(f"BACKUP   {args.backup} complete={backup.is_complete()}", flush=True)
            await asyncio.sleep(args.run)
        finally:
            await app.shutdown()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass


def run_sim(args) -> None:
    """A simulated NCP on a pseudo-terminal (for zigpy/HA development)."""
    import tty

    from ..sim.ncp import SimNcp

    master, slave = os.openpty()
    tty.setraw(master)
    tty.setraw(slave)
    print(f"Simulated NCP on {os.ttyname(slave)} (Ctrl-C to stop)", flush=True)

    class PtyTransport(ByteTransport):
        async def open(self) -> None:
            asyncio.get_running_loop().add_reader(master, self._readable)

        def _readable(self) -> None:
            try:
                data = os.read(master, 4096)
            except OSError:
                return
            if data:
                self.on_data(data)

        def write(self, data: bytes) -> None:
            os.write(master, data)

        async def close(self) -> None:
            asyncio.get_running_loop().remove_reader(master)

    async def main() -> None:
        sim = SimNcp()
        tr = PtyTransport()
        await tr.open()
        sim.attach(tr)
        while True:
            await asyncio.sleep(3600)

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="zigpy-zrhp", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("-p", "--port", default=os.environ.get("ZRHP_PORT"))
    p.add_argument("-b", "--baudrate", type=int, default=921600)
    p.add_argument("--flow-control", choices=("none", "hardware"), default="none")
    p.add_argument("--timeout", type=float, default=5.0, help="handshake timeout")
    p.add_argument("--json", action="store_true")
    p.add_argument("-v", "--verbose", action="count", default=0)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("info")
    c = sub.add_parser("counters")
    c.add_argument("--reset", action="store_true")
    e = sub.add_parser("echo")
    e.add_argument("--count", type=int, default=100)
    e.add_argument("--size", type=int, default=64)
    e.add_argument("--depth", type=int, default=8)
    for name in ("neighbors", "children", "routes"):
        sub.add_parser(name)
    b = sub.add_parser("backup")
    b.add_argument("file")
    r = sub.add_parser("restore")
    r.add_argument("file")
    r.add_argument("--allow-ieee-change", action="store_true")
    r.add_argument("--nwk-margin", type=int, default=10_000)
    r.add_argument("--force", action="store_true")
    f = sub.add_parser("form")
    f.add_argument("--channel", type=int, action="append", default=None)
    f.add_argument("--pan-id", type=lambda s: int(s, 0), default=0xFFFF)
    f.add_argument("--tx-power", type=int, default=8)
    sub.add_parser("init")
    pj = sub.add_parser("permit")
    pj.add_argument("seconds", type=int)
    pj.add_argument("--ncp-only", action="store_true")
    pj.add_argument("--listen", action="store_true")
    li = sub.add_parser("listen")
    li.add_argument("--seconds", type=float, default=30)
    li.add_argument("--log-level", type=int, default=None)
    rs = sub.add_parser("reset")
    rs.add_argument("--mode", choices=("reboot", "bootloader", "factory"), default="reboot")
    rs.add_argument("--hard", action="store_true", help="DTR/RTS reset instead of SYS_RESET")
    sub.add_parser("lock-key-export")
    sub.add_parser("gp-sink-table")
    sub.add_parser("sim")
    a = sub.add_parser("app", help="run zigpy on the NCP (no Home Assistant)")
    a.add_argument("--database", default="~/.zigpy-zrhp/zigbee.db")
    a.add_argument("--pan-id", type=lambda s: int(s, 0), default=None)
    a.add_argument("--channel", type=int, default=None)
    a.add_argument("--form", action="store_true", help="form a network if the NCP has none")
    a.add_argument("--permit", type=int, default=0)
    a.add_argument("--ncp-only", action="store_true", help="permit joins on the NCP only")
    a.add_argument("--backup", default=None, help="write a backup (OCB JSON) to this file")
    a.add_argument("--run", type=float, default=60, help="seconds to keep running")
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=[logging.WARNING, logging.INFO, logging.DEBUG][min(args.verbose, 2)],
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if args.cmd == "sim":
        run_sim(args)
        return
    if not args.port:
        raise SystemExit("--port (or ZRHP_PORT) is required")
    if args.cmd == "app":
        run_app(args)
        return
    if args.cmd == "form" and args.channel is None:
        args.channel = [11, 15, 20, 25]
    handlers = {
        "info": cmd_info,
        "counters": cmd_counters,
        "echo": cmd_echo,
        "neighbors": lambda api, a: _table(api, m.DiagGetNeighborsReq, a),
        "children": lambda api, a: _table(api, m.DiagGetChildrenReq, a),
        "routes": lambda api, a: _table(api, m.DiagGetRoutesReq, a),
        "backup": cmd_backup,
        "restore": cmd_restore,
        "form": cmd_form,
        "init": cmd_init,
        "permit": cmd_permit,
        "listen": cmd_listen,
        "reset": cmd_reset,
        "lock-key-export": cmd_lock,
        "gp-sink-table": cmd_gp,
    }

    async def run() -> None:
        api = await _connect(args)
        try:
            await handlers[args.cmd](api, args)
        finally:
            await api.disconnect()

    try:
        asyncio.run(run())
    except ZrhpError as e:
        print(f"error: {e}", file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
