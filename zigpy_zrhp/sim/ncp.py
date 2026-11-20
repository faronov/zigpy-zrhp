"""A simulated zigbee-rs NCP for tests and development.

It runs the NCP side of the real link layer (:class:`~zigpy_zrhp.link.Link`
with the NCP role) and models enough of ``apps/ncp-coordinator`` to drive the
zigpy library end to end: session, negotiation, formation and resume with
durable frame-counter reservations, permit join, APS data with confirms,
backup export/restore with the counter rules of spec 9.4, the Trust Center
device table, Green Power sink events and simulated devices that answer the
zigpy interview. Behaviour follows the Rust NCP where it is implemented
(for example ``BKP_EXPORT_BEGIN`` needs a running network and
``BKP_RESTORE_BEGIN`` a stopped one).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
import dataclasses
import logging
import os
import random
import struct
from typing import Any

from .. import messages as m
from ..codec import CodecError
from ..frame import ResetReason
from ..link import Data as LinkData, Established, LinkConfig, LinkEvent, PeerChange, PeerReset
from ..records import (
    ChildInfo,
    DeviceFlags,
    DeviceRecord,
    EzspHashedTclkRecord,
    GpdId,
    GpSinkRecord,
    KeyAttrs,
    KeyOrigin,
    LinkBlock,
    NetworkKeyRecord,
    NetworkRecord,
    NodeRecord,
    RecordType,
    RsParamsRecord,
    TcLinkKeyRecord,
    UnknownRecord,
    decode_records,
    encode_record,
    end_record,
    split_records,
)
from ..transport import ByteTransport, LinkDriver
from ..types import (
    FC_STRIDE,
    LOCK_CONFIRM,
    Capacity,
    Endpoint,
    Kind,
    NcpCaps,
    NetworkState,
    Status,
)

LOGGER = logging.getLogger(__name__)

GP_CLUSTER = 0x0021
GP_ENDPOINT = 242
GP_PROFILE = 0xA1E0
#: GP cluster server -> client commands that belong to a sink (7.11 step 4).
GP_SINK_COMMANDS = {0x01, 0x02, 0x06, 0x07, 0x08}

#: ``SimNcp.on_request`` result that drops a request without any response.
SWALLOW = b"<swallow>"

DEFAULT_CAPS = (
    NcpCaps.KEY_EXPORT
    | NcpCaps.IEEE_REWRITABLE
    | NcpCaps.BACKUP_RESTORE
    | NcpCaps.GREEN_POWER_PROXY
    | NcpCaps.GREEN_POWER_SINK
    | NcpCaps.ENERGY_SCAN
    | NcpCaps.TX_POWER
    | NcpCaps.GROUP_MEMBERSHIP
    | NcpCaps.INSTALL_CODES
)


@dataclasses.dataclass
class RestoreModel:
    """NCP-side counter rules of ``BKP_RESTORE_COMMIT`` (spec 9.4)."""

    nwk_fc_start: int
    aps_fc_start: int
    records: list[Any]


def apply_restore(records: list[Any], nwk_margin: int, aps_margin: int) -> RestoreModel:
    """Validate records (rule 2), check ``END`` (rule 4) and compute the starts."""
    if not records or not isinstance(records[-1], type(end_record([]))):
        raise ValueError("missing END")
    body = records[:-1]
    expect = end_record([encode_record(r) for r in body])
    end = records[-1]
    if (end.record_count, end.crc32c) != (expect.record_count, expect.crc32c):
        raise ValueError("END mismatch")
    nwk_in = nwk_floor = aps_max = 0
    for rec in body:
        if isinstance(rec, NodeRecord) and rec.nwk != 0:
            raise ValueError("node NWK must be 0x0000")
        if isinstance(rec, NetworkRecord):
            if rec.security_level != 5:
                raise ValueError("security level must be 5")
            if not 11 <= rec.channel <= 26:
                raise ValueError("invalid channel")
            if rec.pan_id in (0x0000, 0xFFFF):
                raise ValueError("invalid PAN ID")
            if rec.ext_pan_id in (bytes(8), b"\xff" * 8):
                raise ValueError("invalid EPID")
        if isinstance(rec, NetworkKeyRecord):
            if rec.key == bytes(16):
                raise ValueError("all-zero network key")
            nwk_in = rec.tx_counter
        if isinstance(rec, TcLinkKeyRecord):
            aps_max = max(aps_max, rec.tx_counter)
        if isinstance(rec, RsParamsRecord):
            nwk_floor = rec.nwk_fc_limit
            aps_max = max(aps_max, rec.aps_fc_limit)
        if isinstance(rec, DeviceRecord) and rec.link is not None:
            aps_max = max(aps_max, rec.link.tx_counter)
    return RestoreModel(max(nwk_in, nwk_floor) + nwk_margin, aps_max + aps_margin, body)


@dataclasses.dataclass
class TcDevice:
    ieee: bytes
    nwk: int = 0xFFFF
    is_child: bool = False
    capability: int = 0x80
    timeout_exp: int = 8
    key: bytes | None = None
    key_seq: int = 0
    attrs: int = KeyAttrs.VERIFIED
    origin: int = KeyOrigin.TC_GENERATED
    rx_floor: int = 0

    def record(self, aps_limit: int, *, keys: bool = True) -> DeviceRecord:
        flags = (DeviceFlags.IS_CHILD if self.is_child else 0) | (
            DeviceFlags.NWK_VALID if self.nwk != 0xFFFF else 0
        )
        return DeviceRecord(
            ieee=self.ieee,
            nwk=self.nwk,
            flags=int(flags),
            child=ChildInfo(capability=self.capability, timeout_exp=self.timeout_exp)
            if self.is_child
            else None,
            link=LinkBlock(
                key=self.key,
                key_seq=self.key_seq,
                attrs=self.attrs,
                origin=self.origin,
                tx_counter=aps_limit,
                rx_floor=self.rx_floor,
            )
            if (self.key is not None and keys)
            else None,
        )


@dataclasses.dataclass
class SimEndpoint:
    endpoint: int
    profile: int = 0x0104
    device_type: int = 0x0100
    version: int = 0
    in_clusters: list[int] = dataclasses.field(default_factory=lambda: [0x0000, 0x0006])
    out_clusters: list[int] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class SimDevice:
    """A simulated Zigbee device that answers the zigpy interview."""

    ieee: bytes
    nwk: int
    manufacturer: str = "zigbee-rs"
    model: str = "sim-light"
    logical_type: int = 1  # router
    mac_capability: int = 0x8E
    endpoints: list[SimEndpoint] = dataclasses.field(default_factory=lambda: [SimEndpoint(1)])
    lqi: int = 200
    rssi: int = -50
    responsive: bool = True
    received: list[m.Struct] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class NetworkModel:
    pan_id: int = 0
    ext_pan_id: bytes = bytes(8)
    channel: int = 15
    channel_mask: int = 1 << 15
    nwk_update_id: int = 0
    nwk_manager: int = 0
    key: bytes = bytes(16)
    key_seq: int = 0
    tclk: bytes = b"ZigBeeAlliance09"
    tc_ieee: bytes = bytes(8)
    tclk_flags: int = 0
    hashed_seed: bytes | None = None
    tx_power: int = 8


class SimNcp:
    """The simulated NCP. Connect it with :meth:`attach` to a byte transport."""

    def __init__(
        self,
        *,
        ieee: bytes = bytes.fromhex("0807060504030201"),
        caps: int = int(DEFAULT_CAPS),
        fw: str = "0.1.0-sim",
        transport_kind: int = 2,
        uart_baud: int = 921600,
        rng: random.Random | None = None,
    ) -> None:
        self.rng = rng or random.Random(0x5EED)
        self.factory_ieee = ieee
        self.ieee = ieee
        self.ieee_override = False
        self.caps = caps
        self.fw = fw
        self.transport_kind = transport_kind
        self.uart_baud = uart_baud
        self.cookie = self._new_cookie()
        self.reset_reason = 1
        # Durable state ("NV").
        self.formed = False
        self.net = NetworkModel()
        self.nwk_limit = 0
        self.aps_limit = 0
        self.table_epoch = self.rng.getrandbits(32)
        self.devices: dict[bytes, TcDevice] = {}
        self.gp_sink: dict[GpdId, GpSinkRecord] = {}
        # Volatile state.
        self.running = False
        self.nwk_current = 0
        self.aps_current = 0
        self.negotiated = False
        self.host_caps = 0
        self.key_export_locked = False
        self.endpoints: dict[int, m.Struct] = {}
        self.groups: set[tuple[int, int]] = set()
        self.permit_until: float | None = None
        self.permit_log: list[tuple[int, int]] = []
        self.gp_mode = 1
        self.gp_config: m.Struct | None = None
        self.gp_commissioning_until: float | None = None
        self.tc_policy: m.Struct | None = None
        self.retry_cache: dict[tuple[int, int], bytes] = {}
        self.event_seq = {ep: 0 for ep in Endpoint}
        self.sent_aps: list[m.Struct] = []
        self.conflicts: list[m.Struct] = []
        self.requests: list[tuple[int, Any]] = []
        self.sim_devices: dict[int, SimDevice] = {}
        self.busy_next = 0
        self.drop_confirms = False
        self.confirm_delay = 0.005
        self.restore: dict[str, Any] | None = None
        self.export: dict[str, Any] | None = None
        self._txn = 0
        self.last_restore: RestoreModel | None = None
        self.driver: LinkDriver | None = None
        self.on_request: Callable[[m.Message], bytes | None] | None = None
        self.stopped = False
        self._tasks: set[asyncio.Task] = set()

    # --- Wiring -------------------------------------------------------------

    def _new_cookie(self) -> int:
        while True:
            c = self.rng.getrandbits(32)
            if c:
                return c

    def attach(self, transport: ByteTransport) -> None:
        cfg = LinkConfig.ncp()
        self.driver = LinkDriver(transport, cfg, self.cookie, self._on_link_event, txw=16, rxw=16)
        self.driver.start(ResetReason.POWER_ON)

    async def stop(self) -> None:
        self.stopped = True
        for task in list(self._tasks):
            task.cancel()
        if self.driver is not None:
            await self.driver.stop()

    def _spawn(self, coro) -> None:
        task = asyncio.get_running_loop().create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def reboot(self, reason: int = 2, *, keep_link: bool = False) -> None:
        """Reboot: new cookie, volatile state lost, NV kept."""
        self.cookie = self._new_cookie()
        self.reset_reason = reason
        self.running = False
        self.negotiated = False
        self.key_export_locked = False
        self.endpoints.clear()
        self.groups.clear()
        self.permit_until = None
        self.gp_config = None
        self.gp_mode = 1
        self.gp_commissioning_until = None
        self.restore = None
        self.export = None
        self.retry_cache.clear()
        # Resume at the durable limits (no counter reuse).
        self.nwk_current = self.nwk_limit
        self.aps_current = self.aps_limit
        if self.driver is not None:
            self.driver.queues.clear()
            self.driver.link.reopen(self.driver._clock(), self.cookie, ResetReason.POWER_ON)
            self.driver.kick()

    # --- Link events --------------------------------------------------------

    def _on_link_event(self, ev: LinkEvent) -> None:
        if isinstance(ev, PeerReset):
            if ev.change is not PeerChange.RESYNC:
                self.retry_cache.clear()
                self.negotiated = False
        elif isinstance(ev, Established):
            self.event_seq = {ep: 0 for ep in Endpoint}
            self.event(
                m.EvtNcpReady(
                    ncp_cookie=self.cookie,
                    reset_reason=self.reset_reason,
                    network_state=self.network_state,
                    table_epoch=self.table_epoch,
                    nwk_fc_limit=self.nwk_limit,
                    aps_fc_limit=self.aps_limit,
                    dirty_writebacks=0,
                    dropped_indications=0,
                )
            )
        elif isinstance(ev, LinkData):
            try:
                msgs = m.parse_batch(ev.payload)
            except m.BatchError:
                self.event(m.EvtProtocolError(endpoint=int(ev.endpoint), msg_id=0, reason=1))
                return
            for msg in msgs:
                if msg.kind is Kind.REQUEST:
                    self._dispatch(ev.endpoint, msg)

    @property
    def network_state(self) -> int:
        if not self.formed:
            return NetworkState.NONE
        return NetworkState.UP if self.running else NetworkState.FORMED_DOWN

    def event(self, body: m.Struct) -> None:
        if self.driver is None:
            return
        ep = body.endpoint()  # type: ignore[attr-defined]
        self.event_seq[ep] = (self.event_seq[ep] % 0xFFFF) + 1
        msg = m.Message(Kind.EVENT, body.MSG_ID, self.event_seq[ep], body.serialize())  # type: ignore[attr-defined]
        self.driver.send(ep, msg.serialize())

    def _respond(self, ep: Endpoint, msg: m.Message, payload: bytes) -> None:
        self.retry_cache[(msg.tid, msg.msg_id)] = payload
        if len(self.retry_cache) > 64:
            self.retry_cache.pop(next(iter(self.retry_cache)))
        if self.driver is None:
            return
        self.driver.send(ep, m.Message(Kind.RESPONSE, msg.msg_id, msg.tid, payload).serialize())

    def _status(self, ep: Endpoint, msg: m.Message, status: int) -> None:
        self._respond(ep, msg, bytes([status]))

    # --- Dispatch -------------------------------------------------------------

    def _dispatch(self, ep: Endpoint, msg: m.Message) -> None:
        self.requests.append((msg.msg_id, msg))
        home = m.home_endpoint(msg.msg_id)
        if home is None:
            return self._status(ep, msg, Status.UNSUPPORTED_COMMAND)
        if home != ep:
            return self._status(ep, msg, Status.WRONG_ENDPOINT)
        if msg.retry and (msg.tid, msg.msg_id) in self.retry_cache:
            assert self.driver is not None
            payload = self.retry_cache[(msg.tid, msg.msg_id)]
            self.driver.send(ep, m.Message(Kind.RESPONSE, msg.msg_id, msg.tid, payload).serialize())
            return None
        if not self.negotiated and msg.msg_id != m.Id.SYS_NEGOTIATE:
            return self._status(ep, msg, Status.INVALID_STATE)
        if self.on_request is not None:
            override = self.on_request(msg)
            if override is SWALLOW:
                return None
            if override is not None:
                return self._respond(ep, msg, override)
        handler = getattr(self, f"_h_{m.name_of(msg.msg_id).lower()}", None)
        if handler is None:
            return self._status(ep, msg, Status.UNSUPPORTED_COMMAND)
        try:
            body = m.decode_message(msg)
        except CodecError:
            return self._status(ep, msg, Status.INVALID_PARAMETER)
        try:
            result = handler(body, msg)
        except _Reply as r:
            return self._respond(ep, msg, r.payload)
        if result is None:
            return None
        return self._respond(ep, msg, result)

    def ok(self, body: m.Struct | None = None) -> bytes:
        return m.encode_response(body)

    # SYSTEM
    def _h_sys_negotiate(self, req, msg):
        if req.major_min > 1 or req.major_max < 1:
            raise _Reply(bytes([Status.VERSION_MISMATCH]))
        self.negotiated = True
        self.host_caps = req.host_caps
        caps = [
            (Capacity.MAX_APS_INFLIGHT, 16),
            (Capacity.MAX_CHILDREN, 64),
            (Capacity.LINK_KEY_CACHE, 256),
            (Capacity.ADDRESS_MAP_CACHE, 512),
            (Capacity.SOURCE_ROUTE_CACHE, 128),
            (Capacity.MAX_ASDU, 100),
            (Capacity.FC_STRIDE, FC_STRIDE),
            (Capacity.MAX_HOST_ENDPOINTS, 8),
            (Capacity.MAX_RESTORE_RECORDS_PER_PUT, 16),
            (Capacity.GP_SINK_TABLE, 16),
            (Capacity.GP_PROXY_TABLE, 8),
            (Capacity.MAX_NCP_REQUESTS, 8),
            (Capacity.MAX_TC_DEVICES, 256),
        ]
        return self.ok(
            m.SysNegotiateRsp(
                major=1,
                minor=0,
                ncp_caps=self.caps,
                capacities=[m.Capacity(id=int(k), value=v) for k, v in caps],
                fw=self.fw.encode(),
                build_id=bytes.fromhex("0123456789abcdef"),
                chip=1,
            )
        )

    def _h_sys_get_info(self, req, msg):
        return self.ok(
            m.SysGetInfoRsp(
                ieee_factory=self.factory_ieee,
                ieee_active=self.ieee,
                ieee_source=int(self.ieee != self.factory_ieee),
                chip_rev=1,
                flash_size=4 << 20,
                transport=self.transport_kind,
                uart_baud=self.uart_baud if self.transport_kind == 2 else 0,
                uart_flow=1 if self.transport_kind == 2 else 0,
                board=b"sim",
                product=b"zigbee-rs sim NCP",
            )
        )

    def _h_sys_get_status(self, req, msg):
        flags = (
            (1 if self.key_export_locked else 0)
            | (0x08 if self.gp_commissioning_until else 0)
            | (0x10 if self.permit_until else 0)
        )
        return self.ok(
            m.SysGetStatusRsp(
                network_state=self.network_state, uptime_s=1, free_aps_slots=16, flags=flags
            )
        )

    def _h_sys_echo(self, req, msg):
        if len(req.data) > 64:
            raise _Reply(bytes([Status.INVALID_PARAMETER]))
        return self.ok(m.SysEchoRsp(data=req.data))

    def _h_sys_reset(self, req, msg):
        if req.mode not in (0, 1, 2):
            raise _Reply(bytes([Status.INVALID_PARAMETER]))
        ep = Endpoint.SYSTEM
        self._status(ep, msg, Status.SUCCESS)

        async def later() -> None:
            await asyncio.sleep(0.05)
            if req.mode == 2:
                self._wipe()
            await self.reboot(reason=7)

        self._spawn(later())

    def _h_sys_set_ieee(self, req, msg):
        if not self.caps & NcpCaps.IEEE_REWRITABLE:
            raise _Reply(bytes([Status.UNSUPPORTED_COMMAND]))
        if self.running:
            raise _Reply(bytes([Status.INVALID_STATE]))
        self.ieee = self.factory_ieee if req.ieee == b"\xff" * 8 else req.ieee
        self.ieee_override = self.ieee != self.factory_ieee
        return self.ok()

    def _h_sys_set_config(self, req, msg):
        return self.ok(
            m.SysSetConfigRsp(results=[m.ConfigStatus(id=v.id, status=0) for v in req.values])
        )

    def _h_diag_get_counters(self, req, msg):
        assert self.driver is not None
        from ..link import LinkCounters

        counters = [
            m.Counter(id=LinkCounters.IDS[k], value=v)
            for k, v in self.driver.link.counters.as_dict().items()
        ]
        return self.ok(m.DiagGetCountersRsp(counters=counters[:40]))

    def _h_diag_get_neighbors(self, req, msg):
        entries = [
            m.Neighbor(
                ieee=d.ieee,
                nwk=d.nwk,
                device_type=d.logical_type,
                rx_on=1,
                relationship=1 if d.logical_type == 1 else 2,
                lqi=d.lqi,
                outgoing_cost=1,
                age=0,
            )
            for d in self.sim_devices.values()
        ]
        return self.ok(
            m.DiagGetNeighborsRsp(total=len(entries), entries=entries[req.start : req.start + 8])
        )

    def _h_diag_get_routes(self, req, msg):
        return self.ok(m.DiagGetRoutesRsp(total=0, entries=[]))

    def _h_log_config(self, req, msg):
        return self.ok()

    # NETWORK
    def _h_nwk_init(self, req, msg):
        if not self.formed:
            raise _Reply(m.encode_response(m.NwkInitRsp(network_state=0), Status.NOT_FORMED))
        state = self.network_state
        # Floors raise the durable reservations before the first transmission.
        self.nwk_current = max(self.nwk_current, req.nwk_fc_floor, self.nwk_limit)
        self.aps_current = max(self.aps_current, req.aps_fc_floor, self.aps_limit)
        self._reserve(force=True)
        self.running = True
        self._respond(Endpoint.ZIGBEE, msg, self.ok(m.NwkInitRsp(network_state=state)))
        self.event(m.EvtNetworkState(state=2, reason=0, zb_status=0, req_tid=msg.tid))

    def _h_nwk_form(self, req, msg):
        if self.formed:
            raise _Reply(bytes([Status.INVALID_STATE]))
        channels = [c for c in range(11, 27) if req.channel_mask & (1 << c)] or [15]
        self.net = NetworkModel(
            pan_id=req.pan_id if req.pan_id != 0xFFFF else self.rng.randrange(1, 0xFFFE),
            ext_pan_id=req.ext_pan_id if req.ext_pan_id != bytes(8) else os.urandom(8),
            channel=channels[0],
            channel_mask=req.channel_mask,
            nwk_update_id=req.nwk_update_id,
            nwk_manager=req.nwk_manager,
            key=req.network_key if req.network_key != bytes(16) else os.urandom(16),
            key_seq=req.key_seq,
            tc_ieee=self.ieee,
            tx_power=req.tx_power,
        )
        self.formed = True
        self.running = True
        self._reserve(force=True)
        self._respond(Endpoint.ZIGBEE, msg, self.ok())
        self.event(m.EvtNetworkState(state=2, reason=0, zb_status=0, req_tid=msg.tid))

    def _wipe(self) -> None:
        self.formed = False
        self.running = False
        self.devices.clear()
        self.gp_sink.clear()
        self.table_epoch = (self.table_epoch + 1) & 0xFFFFFFFF

    def _h_nwk_leave_reset(self, req, msg):
        self._wipe()
        if not req.flags & 0x02:
            self.endpoints.clear()
        self._respond(Endpoint.ZIGBEE, msg, self.ok())
        self.event(m.EvtTblEpochChanged(new_epoch=self.table_epoch, reason=1))

    def _h_nwk_get_info(self, req, msg):
        n = self.net
        if not self.running:
            # Like the real NCP: the live NIB is only populated by NWK_INIT,
            # so a formed-but-down network reads back as unconfigured.
            return self.ok(
                m.NwkGetInfoRsp(
                    state=self.network_state,
                    pan_id=0xFFFF,
                    ext_pan_id=bytes(8),
                    channel=0,
                    channel_mask=n.channel_mask,
                    short=0xFFFF,
                    ieee=self.ieee,
                    nwk_update_id=0,
                    nwk_manager=0,
                    key_seq=0,
                    security_level=5,
                    tx_power=n.tx_power,
                    stack_profile=2,
                )
            )
        return self.ok(
            m.NwkGetInfoRsp(
                state=self.network_state,
                pan_id=n.pan_id,
                ext_pan_id=n.ext_pan_id,
                channel=n.channel,
                channel_mask=n.channel_mask,
                short=0x0000,
                ieee=self.ieee,
                nwk_update_id=n.nwk_update_id,
                nwk_manager=n.nwk_manager,
                key_seq=n.key_seq,
                security_level=5,
                tx_power=n.tx_power,
                stack_profile=2,
            )
        )

    def _h_nwk_permit_join(self, req, msg):
        if not self.running:
            raise _Reply(bytes([Status.INVALID_STATE]))
        if req.target not in (0x0000, 0xFFFC):
            raise _Reply(bytes([Status.UNSUPPORTED_COMMAND]))
        loop = asyncio.get_running_loop()
        self.permit_until = loop.time() + req.duration_s if req.duration_s else None
        self.permit_log.append((req.duration_s, req.target))
        self._respond(Endpoint.ZIGBEE, msg, self.ok())
        self.event(m.EvtPermitJoinState(remaining_s=req.duration_s))

    def _h_nwk_add_endpoint(self, req, msg):
        if not 1 <= req.ep <= 240 or len(req.in_clusters) > 16 or len(req.out_clusters) > 16:
            raise _Reply(bytes([Status.INVALID_PARAMETER]))
        if req.ep not in self.endpoints and len(self.endpoints) >= 8:
            raise _Reply(bytes([Status.NO_SPACE]))
        self.endpoints[req.ep] = req
        return self.ok()

    def _h_nwk_group_membership(self, req, msg):
        if req.op == 1:
            self.groups.add((req.group, req.ep))
        elif req.op == 2:
            self.groups.discard((req.group, req.ep))
        elif req.op == 3:
            self.groups.clear()
        return self.ok()

    def _h_nwk_set_tx_power(self, req, msg):
        self.net.tx_power = max(-20, min(20, req.dbm))
        return self.ok(m.NwkSetTxPowerRsp(applied_dbm=self.net.tx_power))

    def _h_nwk_energy_scan(self, req, msg):
        if not self.running:
            raise _Reply(bytes([Status.INVALID_STATE]))
        self._respond(Endpoint.ZIGBEE, msg, self.ok())
        channels = [c for c in range(11, 27) if req.channel_mask & (1 << c)]
        results = [
            m.EnergyResult(channel=c, max_rssi_dbm=-90 + (c * 7) % 30, energy=(c * 37) % 200)
            for c in channels
        ]
        self.event(m.EvtEnergyScanResult(req_tid=msg.tid, status=0, results=results))

    def _h_nwk_change_channel(self, req, msg):
        self._respond(Endpoint.ZIGBEE, msg, self.ok())
        self.net.channel = req.channel
        self.net.nwk_update_id = req.nwk_update_id or (self.net.nwk_update_id + 1) & 0xFF
        self.event(
            m.EvtChannelChanged(
                channel=req.channel, nwk_update_id=self.net.nwk_update_id, req_tid=msg.tid
            )
        )

    def _h_nwk_remove_device(self, req, msg):
        self.devices.pop(req.ieee, None)
        return self.ok()

    # DATA
    def _h_aps_data_request(self, req, msg):
        if not self.running:
            raise _Reply(bytes([Status.INVALID_STATE]))
        if req.profile == 0 and req.dst_mode == m.AddrMode.NWK and req.dst == 0x0000:
            raise _Reply(bytes([Status.INVALID_PARAMETER]))
        if req.dst_mode == m.AddrMode.IEEE and req.dst == self.ieee and req.profile == 0:
            raise _Reply(bytes([Status.INVALID_PARAMETER]))
        if self.gp_mode == 1 and _is_gp_sink_frame(req):
            self.conflicts.append(req)
            raise _Reply(bytes([Status.CONFLICT]))
        if self.busy_next > 0:
            self.busy_next -= 1
            raise _Reply(bytes([Status.BUSY]))
        if len(req.asdu) > 100 and not req.tx_options & 0x08:
            raise _Reply(bytes([Status.TOO_LARGE]))
        self.sent_aps.append(req)
        self._use_counter()
        self._respond(Endpoint.ZIGBEE, msg, self.ok())
        self._spawn(self._deliver(req, msg.tid))

    async def _deliver(self, req, tid: int) -> None:
        await asyncio.sleep(self.confirm_delay)
        dev = None
        if req.dst_mode == m.AddrMode.NWK:
            dev = self.sim_devices.get(req.dst)
        elif req.dst_mode == m.AddrMode.IEEE:
            dev = next((d for d in self.sim_devices.values() if d.ieee == req.dst), None)
        unicast = req.dst_mode in (m.AddrMode.NWK, m.AddrMode.IEEE)
        ok = (not unicast) or (dev is not None and dev.responsive)
        if not self.drop_confirms:
            self.event(
                m.EvtApsDataConfirm(
                    req_tid=tid,
                    status=0 if ok else 1,
                    zb_status=0 if ok else 0xA7,
                    aps_counter=tid & 0xFF,
                    dst_nwk=dev.nwk if dev else (req.dst if isinstance(req.dst, int) else 0xFFFF),
                    flags=1 if (ok and unicast and req.tx_options & 1) else 0,
                    elapsed_ms=5,
                )
            )
        if dev is not None and dev.responsive:
            dev.received.append(req)
            for reply in _device_replies(dev, req):
                await asyncio.sleep(0.002)
                self.indication(dev, *reply)

    def indication(
        self,
        dev: SimDevice,
        profile: int,
        cluster: int,
        src_ep: int,
        dst_ep: int,
        asdu: bytes,
        *,
        dst_mode: int = 0x02,
        dst: int = 0x0000,
        flags: int = 0x06,
    ) -> None:
        self.event(
            m.EvtApsDataIndication(
                dst_mode=dst_mode,
                dst=dst,
                dst_ep=dst_ep,
                src_nwk=dev.nwk,
                src_ieee=dev.ieee,
                src_ep=src_ep,
                profile=profile,
                cluster=cluster,
                flags=flags,
                lqi=dev.lqi,
                rssi=dev.rssi,
                last_hop_nwk=dev.nwk,
                aps_counter=self.rng.randrange(256),
                key_source=0,
                rx_time_ms=0,
                asdu=asdu,
            )
        )

    # Frame counters with durable reservations (8.4).
    def _reserve(self, *, force: bool = False) -> None:
        if force or self.nwk_current >= self.nwk_limit:
            self.nwk_limit = self.nwk_current + FC_STRIDE
            self.event(
                m.EvtFcCheckpoint(
                    domain=1, key_seq=self.net.key_seq, durable_limit=self.nwk_limit, generation=0
                )
            )
        if force or self.aps_current >= self.aps_limit:
            self.aps_limit = self.aps_current + FC_STRIDE
            self.event(
                m.EvtFcCheckpoint(
                    domain=2, key_seq=self.net.key_seq, durable_limit=self.aps_limit, generation=0
                )
            )

    def _use_counter(self, n: int = 1) -> None:
        self.nwk_current += n
        if self.nwk_current >= self.nwk_limit:
            self._reserve()

    # SECURITY
    def _keys_allowed(self) -> bool:
        return bool(self.caps & NcpCaps.KEY_EXPORT) and not self.key_export_locked

    def _h_sec_get_network_key(self, req, msg):
        if not self._keys_allowed():
            raise _Reply(bytes([Status.ACCESS_DENIED]))
        if not self.formed:
            raise _Reply(bytes([Status.NOT_FORMED]))
        return self.ok(
            m.SecGetNetworkKeyRsp(
                key=self.net.key, seq=self.net.key_seq, nwk_fc_limit=self.nwk_limit
            )
        )

    def _h_sec_get_frame_counters(self, req, msg):
        return self.ok(
            m.SecGetFrameCountersRsp(
                nwk_current=self.nwk_current,
                nwk_limit=self.nwk_limit,
                aps_current=self.aps_current,
                aps_limit=self.aps_limit,
                stride=FC_STRIDE,
            )
        )

    def _h_sec_lock_key_export(self, req, msg):
        if req.confirm != LOCK_CONFIRM:
            raise _Reply(bytes([Status.INVALID_PARAMETER]))
        self.key_export_locked = True
        return self.ok()

    def _h_sec_set_tc_policy(self, req, msg):
        self.tc_policy = req
        return self.ok()

    def _h_sec_add_link_key(self, req, msg):
        dev = self.devices.setdefault(req.ieee, TcDevice(ieee=req.ieee))
        dev.key = req.key
        dev.origin = KeyOrigin.IMPORTED
        dev.attrs = req.attrs
        return self.ok()

    def _h_sec_add_install_code(self, req, msg):
        from ..crypto import install_code_key

        if len(req.code) not in (8, 10, 14, 18):
            raise _Reply(bytes([Status.INVALID_PARAMETER]))
        key = install_code_key(req.code)
        dev = self.devices.setdefault(req.ieee, TcDevice(ieee=req.ieee))
        dev.key = key
        dev.origin = KeyOrigin.INSTALL_CODE
        return self.ok(m.SecAddInstallCodeRsp(derived_key=key))

    # TABLES
    def _h_tbl_sync(self, req, msg):
        return self.ok(
            m.TblSyncRsp(
                ncp_table_epoch=self.table_epoch,
                host_acked_rev=0,
                dirty=0,
                cached_devices=len(self.devices),
                cached_routes=0,
                paging_active=0,
            )
        )

    def _h_tbl_invalidate(self, req, msg):
        if req.key.key_type == 1:
            self.devices.pop(req.key.key, None)
        else:
            for k, d in list(self.devices.items()):
                if d.nwk == req.key.key:
                    del self.devices[k]
        return self.ok()

    def _h_tbl_stats(self, req, msg):
        return self.ok(m.TblStatsRsp(capacity=256, used=len(self.devices)))

    # BACKUP
    def _h_bkp_export_begin(self, req, msg):
        if not self.running:
            raise _Reply(bytes([Status.INVALID_STATE]))
        keys = bool(req.flags & 0x01) and self._keys_allowed()
        records = self.export_records(
            keys=keys, devices=bool(req.flags & 0x02), gp=bool(req.flags & 0x04)
        )
        self._txn += 1
        tlvs = [encode_record(r) for r in records]
        self.export = {"txn": self._txn, "tlvs": tlvs, "next": 0}
        return self.ok(m.BkpExportBeginRsp(txn=self._txn, record_count=len(records)))

    def export_records(
        self, *, keys: bool = True, devices: bool = True, gp: bool = False
    ) -> list[Any]:
        n = self.net
        recs: list[Any] = [
            NodeRecord(ieee=self.ieee, nwk=0, logical_type=0, flags=int(self.ieee_override)),
            NetworkRecord(
                pan_id=n.pan_id,
                ext_pan_id=n.ext_pan_id,
                channel=n.channel,
                channel_mask=n.channel_mask,
                nwk_update_id=n.nwk_update_id,
                nwk_manager=n.nwk_manager,
                security_level=5,
                tx_power=n.tx_power,
            ),
        ]
        if keys:
            recs.append(
                NetworkKeyRecord(key=n.key, seq=n.key_seq, tx_counter=self.nwk_limit, flags=1)
            )
            recs.append(
                TcLinkKeyRecord(
                    key=n.tclk, tc_ieee=n.tc_ieee, tx_counter=self.aps_limit, flags=n.tclk_flags
                )
            )
            if n.hashed_seed is not None:
                recs.append(EzspHashedTclkRecord(seed=n.hashed_seed))
        recs.append(
            RsParamsRecord(
                fc_stride=FC_STRIDE,
                table_epoch=self.table_epoch,
                nwk_fc_limit=self.nwk_limit,
                aps_fc_limit=self.aps_limit,
                flags=int(bool(self.host_caps & 1)),
            )
        )
        if devices:
            for d in sorted(self.devices.values(), key=lambda d: d.ieee[::-1]):
                recs.append(d.record(self.aps_limit, keys=keys))
        if gp:
            for rec in self.gp_sink.values():
                recs.append(rec if keys else rec.replace(key=None))
        recs.append(end_record([encode_record(r) for r in recs]))
        return recs

    def _h_bkp_export_read(self, req, msg):
        ex = self.export
        if ex is None or ex["txn"] != req.txn:
            raise _Reply(bytes([Status.NOT_FOUND]))
        limit = max(32, min(req.max_bytes, 600))
        out = bytearray()
        while ex["next"] < len(ex["tlvs"]):
            tlv = ex["tlvs"][ex["next"]]
            if out and len(out) + len(tlv) > limit:
                break
            out += tlv
            ex["next"] += 1
        more = int(ex["next"] < len(ex["tlvs"]))
        return bytes([0, more]) + bytes(out)

    def _h_bkp_export_end(self, req, msg):
        if self.export is None or self.export["txn"] != req.txn:
            raise _Reply(bytes([Status.NOT_FOUND]))
        self.export = None
        return self.ok()

    def _h_bkp_restore_begin(self, req, msg):
        if self.restore is not None:
            raise _Reply(bytes([Status.IN_PROGRESS]))
        if self.running:
            raise _Reply(bytes([Status.INVALID_STATE]))
        self._txn += 1
        self.restore = {"txn": self._txn, "req": req, "records": []}
        return self.ok(m.BkpRestoreBeginRsp(txn=self._txn, max_records_per_put=16))

    def _h_bkp_restore_put(self, req, msg):
        r = self.restore
        if r is None or r["txn"] != req.txn:
            raise _Reply(bytes([Status.NOT_FOUND]))
        try:
            recs = decode_records(req.records)
        except CodecError:
            self.restore = None
            raise _Reply(bytes([Status.INVALID_PARAMETER])) from None
        notes = []
        for rec in recs:
            idx = len(r["records"])
            r["records"].append(rec)
            if isinstance(rec, UnknownRecord):
                notes.append(m.RestoreNoteEntry(index=idx, note=3))
        return self.ok(m.BkpRestorePutRsp(accepted=len(recs), notes=notes))

    def _h_bkp_restore_abort(self, req, msg):
        if self.restore is None or self.restore["txn"] != req.txn:
            raise _Reply(bytes([Status.NOT_FOUND]))
        self.restore = None
        return self.ok()

    def _h_bkp_restore_commit(self, req, msg):
        r = self.restore
        if r is None or r["txn"] != req.txn:
            raise _Reply(bytes([Status.NOT_FOUND]))
        self.restore = None
        try:
            model = apply_restore(r["records"], r["req"].nwk_margin, r["req"].aps_margin)
        except ValueError:
            raise _Reply(bytes([Status.INVALID_PARAMETER])) from None
        self.last_restore = model
        allow_ieee = bool(r["req"].flags & 0x01)
        net = NetworkModel()
        devices: dict[bytes, TcDevice] = {}
        gp: dict[GpdId, GpSinkRecord] = {}
        for rec in model.records:
            if isinstance(rec, NodeRecord):
                if rec.ieee != self.ieee:
                    if not (allow_ieee and self.caps & NcpCaps.IEEE_REWRITABLE):
                        raise _Reply(bytes([Status.SECURITY_ERROR]))
                    self.ieee = rec.ieee
                if rec.flags & 0x01 and allow_ieee:
                    self.ieee_override = True
            elif isinstance(rec, NetworkRecord):
                net.pan_id, net.ext_pan_id, net.channel = rec.pan_id, rec.ext_pan_id, rec.channel
                net.channel_mask, net.nwk_update_id = rec.channel_mask, rec.nwk_update_id
                net.nwk_manager = rec.nwk_manager
                net.tx_power = rec.tx_power if rec.tx_power != 0x7F else 8
            elif isinstance(rec, NetworkKeyRecord):
                net.key, net.key_seq = rec.key, rec.seq
            elif isinstance(rec, TcLinkKeyRecord):
                net.tclk, net.tc_ieee, net.tclk_flags = rec.key, rec.tc_ieee, rec.flags
            elif isinstance(rec, EzspHashedTclkRecord):
                net.hashed_seed = rec.seed
            elif isinstance(rec, DeviceRecord):
                devices[rec.ieee] = TcDevice(
                    ieee=rec.ieee,
                    nwk=rec.nwk,
                    is_child=rec.is_child,
                    capability=rec.child.capability if rec.child else 0x80,
                    timeout_exp=rec.child.timeout_exp if rec.child else 8,
                    key=rec.link.key if rec.link else None,
                    key_seq=rec.link.key_seq if rec.link else 0,
                    attrs=rec.link.attrs if rec.link else KeyAttrs.VERIFIED,
                    origin=rec.link.origin if rec.link else KeyOrigin.IMPORTED,
                    rx_floor=rec.link.rx_floor if rec.link else 0,
                )
            elif isinstance(rec, GpSinkRecord):
                gp[rec.gpd_id] = rec
        self.net = net
        self.devices = devices
        self.gp_sink = gp
        self.formed = True
        self.running = False
        self.nwk_current = model.nwk_fc_start
        self.aps_current = model.aps_fc_start
        self.nwk_limit = model.nwk_fc_start + FC_STRIDE
        self.aps_limit = model.aps_fc_start + FC_STRIDE
        self.table_epoch = (self.table_epoch + 1) & 0xFFFFFFFF
        keys = sum(1 for d in devices.values() if d.key is not None)
        children = sum(1 for d in devices.values() if d.is_child)
        self._respond(
            Endpoint.BULK,
            msg,
            self.ok(
                m.BkpRestoreCommitRsp(
                    nwk_fc_start=model.nwk_fc_start,
                    aps_fc_start=model.aps_fc_start,
                    link_keys_on_ncp=keys,
                    link_keys_host_backed=0,
                    children=children,
                )
            ),
        )
        self.event(m.EvtTblEpochChanged(new_epoch=self.table_epoch, reason=2))

    # GREEN POWER
    def _h_gp_sink_config(self, req, msg):
        if req.security_level & 0x08:
            raise _Reply(bytes([Status.UNSUPPORTED_COMMAND]))
        self.gp_mode = req.mode
        self.gp_config = req
        return self.ok()

    def _h_gp_sink_commissioning(self, req, msg):
        if not self.running or self.gp_mode != 1:
            raise _Reply(bytes([Status.INVALID_STATE]))
        loop = asyncio.get_running_loop()
        if req.action == 1:
            window = req.window_s or 180
            self.gp_commissioning_until = loop.time() + window
            self._respond(Endpoint.ZIGBEE, msg, self.ok())
            self.event(
                m.EvtGpCommissioning(
                    state=1, window_s=window, involve_proxies=req.flags & 1, exit_reason=0
                )
            )
        else:
            self.gp_commissioning_until = None
            self._respond(Endpoint.ZIGBEE, msg, self.ok())
            self.event(
                m.EvtGpCommissioning(state=0, window_s=0xFFFF, involve_proxies=0, exit_reason=1)
            )

    def _h_gp_sink_table_read(self, req, msg):
        recs = list(self.gp_sink.values())
        if self.key_export_locked:
            recs = [r.replace(key=None) for r in recs]
        return self.ok(
            m.GpSinkTableReadRsp(total=len(recs), records=recs[req.start : req.start + 8])
        )

    def _h_gp_sink_table_put(self, req, msg):
        if not self.running:
            raise _Reply(bytes([Status.INVALID_STATE]))
        statuses = []
        for rec in req.records:
            if not isinstance(rec, GpSinkRecord):
                statuses.append(Status.INVALID_PARAMETER)
            elif rec.gpd_id in self.gp_sink:
                statuses.append(Status.ALREADY_EXISTS)
            elif len(self.gp_sink) >= 16:
                statuses.append(Status.NO_SPACE)
            else:
                self.gp_sink[rec.gpd_id] = rec
                statuses.append(Status.SUCCESS)
        return self.ok(m.GpSinkTablePutRsp(statuses=[int(s) for s in statuses]))

    def _h_gp_sink_remove(self, req, msg):
        if not self.running:
            raise _Reply(bytes([Status.INVALID_STATE]))
        if self.gp_sink.pop(req.gpd_id, None) is None:
            raise _Reply(bytes([Status.NOT_FOUND]))
        self._respond(Endpoint.ZIGBEE, msg, self.ok())
        self.event(m.EvtGpDecommissioned(gpd_id=req.gpd_id))

    # --- Simulation API -------------------------------------------------------

    def add_device(self, dev: SimDevice) -> SimDevice:
        self.sim_devices[dev.nwk] = dev
        return dev

    def join(self, dev: SimDevice, *, parent: int = 0x0000, unique_key: bool = True) -> None:
        """A device joins: TC events, Device_annce indication."""
        self.add_device(dev)
        is_child = parent == 0x0000
        tc = self.devices.setdefault(dev.ieee, TcDevice(ieee=dev.ieee))
        tc.nwk = dev.nwk
        tc.is_child = is_child
        tc.capability = dev.mac_capability
        if unique_key:
            tc.key = self.rng.randbytes(16)
        self.event(
            m.EvtDeviceJoined(
                nwk=dev.nwk,
                ieee=dev.ieee,
                parent_nwk=parent,
                join_type=0,
                capability=dev.mac_capability if is_child else 0,
                decision=0,
            )
        )
        self.event(
            m.EvtDeviceAuthorized(
                nwk=dev.nwk,
                ieee=dev.ieee,
                result=1 if unique_key else 0,
                link_key_type=int(unique_key),
            )
        )
        annce = bytes([0x80]) + struct.pack("<H", dev.nwk) + dev.ieee + bytes([dev.mac_capability])
        self.indication(dev, 0, 0x0013, 0, 0, annce, dst_mode=0x0F, dst=0xFFFD, flags=0x0E)

    def leave(self, dev: SimDevice, *, rejoin: bool = False) -> None:
        self.devices.pop(dev.ieee, None)
        self.sim_devices.pop(dev.nwk, None)
        self.event(m.EvtDeviceLeft(nwk=dev.nwk, ieee=dev.ieee, flags=int(rejoin), reason=1))

    def report(self, dev: SimDevice, ep: int, cluster: int, zcl: bytes) -> None:
        self.indication(dev, 0x0104, cluster, ep, 1, zcl)

    def gp_frame(
        self,
        src_id: int,
        command_id: int,
        payload: bytes = b"",
        *,
        result: int = 1,
        frame_counter: int = 0,
        security_level: int = 0,
        key_type: int = 0,
        device_id: int = 0x02,
        rx_after_tx: bool = False,
        proxy_nwk: int = 0xFFFF,
        origin: int = 1,
    ) -> None:
        flags = int(rx_after_tx) | (0x02 if security_level >= 2 else 0)
        self.event(
            m.EvtGpFrame(
                origin=origin if proxy_nwk == 0xFFFF else 2,
                result=result,
                gpd_id=GpdId.srcid(src_id),
                device_id=device_id,
                command_id=command_id,
                frame_counter=frame_counter,
                security_level=security_level,
                key_type=key_type,
                flags=flags,
                proxy_nwk=proxy_nwk,
                gpp_gpd_link=0xFF,
                rssi=-128,
                lqi=180,
                payload=payload,
            )
        )

    def gp_commission(
        self,
        src_id: int,
        commissioning_payload: bytes,
        *,
        device_id: int = 0x02,
        security_level: int = 0,
        key_type: int = 0,
        key: bytes | None = None,
        frame_counter: int = 0,
        mac_seq: int = 1,
        flags: int = 0x01,
    ) -> GpSinkRecord | None:
        """The NCP sink commissions a GPD (unidirectional) and reports it."""
        loop = asyncio.get_running_loop()
        if self.gp_commissioning_until is None or loop.time() > self.gp_commissioning_until:
            return None
        rec = GpSinkRecord(
            gpd_id=GpdId.srcid(src_id),
            device_id=device_id,
            communication_mode=2,
            group=0x0B84,
            assigned_alias=0xFFFF,
            flags=flags,
            security_level=security_level,
            key_type=key_type,
            key=key,
            frame_counter=frame_counter,
            groupcast_radius=0,
        )
        self.gp_sink[rec.gpd_id] = rec
        self.gp_frame(
            src_id,
            0xE0,
            commissioning_payload,
            result=2,
            frame_counter=mac_seq,
            device_id=device_id,
        )
        self.event(
            m.EvtGpCommissioned(
                gpd_id=rec.gpd_id,
                device_id=device_id,
                flags=0x02 if key is not None and not self.key_export_locked else 0,
                record=rec if not self.key_export_locked else rec.replace(key=None),
            )
        )
        if self.gp_config is not None and self.gp_config.exit_mode & 0x02:
            self.gp_commissioning_until = None
            self.event(
                m.EvtGpCommissioning(state=0, window_s=0xFFFF, involve_proxies=0, exit_reason=2)
            )
        return rec


class _Reply(Exception):
    def __init__(self, payload: bytes) -> None:
        self.payload = payload


def _is_gp_sink_frame(req) -> bool:
    """zigpy sink transmissions the NCP sink refuses with CONFLICT (7.11 step 5)."""
    if req.profile == GP_PROFILE and req.cluster == GP_CLUSTER and req.src_ep == GP_ENDPOINT:
        asdu = req.asdu
        if len(asdu) >= 3 and asdu[0] & 0x08:  # server -> client
            return asdu[2] in GP_SINK_COMMANDS
    return False


def _device_replies(dev: SimDevice, req) -> list[tuple[int, int, int, int, bytes]]:
    """ZDO / Basic replies of a simulated device (profile, cluster, src_ep, dst_ep, asdu)."""
    asdu = req.asdu
    out: list[tuple[int, int, int, int, bytes]] = []
    if req.profile == 0 and asdu:
        tsn = asdu[0]
        cluster = req.cluster
        nwk = struct.pack("<H", dev.nwk)
        if cluster == 0x0002:  # Node_Desc_req
            desc = bytes([dev.logical_type, 0x40, dev.mac_capability]) + struct.pack(
                "<HBHHHB", 0x1234, 82, 128, 0x0000, 128, 0
            )
            out.append((0, 0x8002, 0, 0, bytes([tsn, 0]) + nwk + desc))
        elif cluster == 0x0005:  # Active_EP_req
            eps = bytes(e.endpoint for e in dev.endpoints)
            out.append((0, 0x8005, 0, 0, bytes([tsn, 0]) + nwk + bytes([len(eps)]) + eps))
        elif cluster == 0x0004:  # Simple_Desc_req
            ep_id = asdu[3]
            ep = next((e for e in dev.endpoints if e.endpoint == ep_id), None)
            if ep is None:
                out.append((0, 0x8004, 0, 0, bytes([tsn, 0x83]) + nwk + b"\x00"))
            else:
                body = struct.pack("<BHHB", ep.endpoint, ep.profile, ep.device_type, ep.version)
                body += bytes([len(ep.in_clusters)]) + b"".join(
                    struct.pack("<H", c) for c in ep.in_clusters
                )
                body += bytes([len(ep.out_clusters)]) + b"".join(
                    struct.pack("<H", c) for c in ep.out_clusters
                )
                out.append((0, 0x8004, 0, 0, bytes([tsn, 0]) + nwk + bytes([len(body)]) + body))
        elif cluster == 0x0021:  # Bind_req
            out.append((0, 0x8021, 0, 0, bytes([tsn, 0])))
        elif cluster == 0x0034:  # Mgmt_Leave_req
            out.append((0, 0x8034, 0, 0, bytes([tsn, 0])))
        elif cluster == 0x0031:  # Mgmt_Lqi_req
            out.append((0, 0x8031, 0, 0, bytes([tsn, 0, 0, 0, 0])))
        elif cluster == 0x0032:  # Mgmt_Rtg_req
            out.append((0, 0x8032, 0, 0, bytes([tsn, 0, 0, 0, 0])))
        elif cluster == 0x0036:  # Mgmt_Permit_Joining_req
            out.append((0, 0x8036, 0, 0, bytes([tsn, 0])))
    elif req.profile in (0x0104, 0xC05E) and len(asdu) >= 3:
        fc, tsn, cmd = asdu[0], asdu[1], asdu[2]
        if fc & 0x04:  # manufacturer specific: not modelled
            return out
        if req.cluster == 0x0000 and cmd == 0x00 and not fc & 0x01:  # Read Attributes
            records = b""
            for i in range(3, len(asdu) - 1, 2):
                attr = struct.unpack_from("<H", asdu, i)[0]
                value = {0x0004: dev.manufacturer, 0x0005: dev.model}.get(attr)
                if value is None:
                    records += struct.pack("<HB", attr, 0x86)
                else:
                    raw = value.encode()
                    records += struct.pack("<HBB", attr, 0, 0x42) + bytes([len(raw)]) + raw
            out.append(
                (req.profile, 0x0000, req.dst_ep, req.src_ep, bytes([0x18, tsn, 0x01]) + records)
            )
        elif cmd == 0x06 and not fc & 0x01:  # Configure Reporting
            out.append(
                (req.profile, req.cluster, req.dst_ep, req.src_ep, bytes([0x18, tsn, 0x07, 0x00]))
            )
        elif fc & 0x01 and not fc & 0x10:  # cluster-specific: default response
            out.append(
                (
                    req.profile,
                    req.cluster,
                    req.dst_ep,
                    req.src_ep,
                    bytes([0x18, tsn, 0x0B, cmd, 0x00]),
                )
            )
    return out


def split_tlvs(stream: bytes) -> list[tuple[int, bytes]]:
    return split_records(stream)


__all__ = [
    "RecordType",
    "SimDevice",
    "SimEndpoint",
    "SimNcp",
    "TcDevice",
    "apply_restore",
]
