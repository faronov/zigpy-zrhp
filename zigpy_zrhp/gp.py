"""Green Power: the NCP sink is authoritative and zigpy is its shadow (spec 7.11).

* ``EVT_GP_FRAME`` becomes a :class:`zigpy.types.ZigbeeGpPacket` for
  ``app.gp_packet_received`` (commissioning frames and operational frames).
* zigpy's own sink transmissions (GP Pairing, Proxy Commissioning Mode, GP
  Response, Translation Table commands, the alias ``Device_annce``) are
  swallowed and reported as sent; a GP Pairing that removes a GPD becomes
  ``GP_SINK_REMOVE``.
* With the "sink on radio" hook of the ``faronov/zigpy`` fork
  (``ControllerApplication.gp_radio_sink``) zigpy delegates permit and unpair
  to :class:`RadioSink` and transmits nothing itself; swallowing stays as a
  second guard.
* Start and resume reconcile ``GP_SINK_TABLE_READ`` with zigpy's GP devices.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

import zigpy.application
from zigpy.device import GreenPowerDevice
import zigpy.types as t
from zigpy.zgp.types import (
    ApplicationID,
    GPDCommandID,
    SecurityKeyType,
    SecurityLevel,
    SecurityStatus,
    SrcID,
)
from zigpy.zgp.util import synthetic_ieee

from . import messages as m
from .api import ZrhpError
from .records import GpdId, GpSinkFlags, GpSinkRecord
from .types import Status

if TYPE_CHECKING:
    from .zigbee.application import ControllerApplication

LOGGER = logging.getLogger(__name__)

GP_PROFILE = 0xA1E0
GP_CLUSTER = 0x0021
GP_ENDPOINT = 242
GP_GROUP = 0x0B84
#: GP cluster server -> client commands that only a sink sends.
SINK_COMMANDS = {
    0x01: "GP Pairing",
    0x02: "GP Proxy Commissioning Mode",
    0x06: "GP Response",
    0x07: "GP Translation Table Update",
    0x08: "GP Translation Table Request",
}
#: ``EVT_GP_FRAME.result`` values fed to zigpy.
FED_RESULTS = {0, 1, 2, 3, 4, 5}
COMMISSIONING_COMMANDS = {0xE0, 0xE2, 0xE3}

#: ``GP_SINK_CONFIG.exit_mode``: on window expiry | on GP Proxy Commissioning Mode exit.
EXIT_MODE = 0x05
COMMISSIONING_WINDOW = 180


def zigpy_has_radio_sink_hook() -> bool:
    """``True`` with the ``faronov/zigpy`` fork's "sink on radio" hook."""
    return hasattr(zigpy.application.ControllerApplication, "gp_radio_sink")


def gpd_key(gpd_id: GpdId) -> bytes:
    return GpdId.pack(gpd_id)


def gp_packet_from_event(evt: Any) -> t.ZigbeeGpPacket:
    """``EVT_GP_FRAME`` -> zigpy GP packet (already authenticated and de-duplicated)."""
    level = SecurityLevel(evt.security_level & 0x03)
    secured = level in (SecurityLevel.FullFrameCounterAndMIC, SecurityLevel.Encrypted)
    kwargs: dict[str, Any] = {
        "command_id": GPDCommandID(evt.command_id),
        "payload": t.SerializableBytes(evt.payload),
        "frame_counter": t.uint32_t(evt.frame_counter),
        "security_level": level,
        "security_key_type": SecurityKeyType(evt.key_type & 0x07)
        if secured
        else SecurityKeyType.NoKey,
        "security_status": SecurityStatus.SecuritySuccess if secured else SecurityStatus.NoSecurity,
        "rx_after_tx": bool(evt.flags & 0x01),
        "lqi": t.uint8_t(evt.lqi),
        "rssi": None if evt.rssi == -128 else t.int8s(evt.rssi),
        "gpp_short_addr": None if evt.proxy_nwk == 0xFFFF else t.NWK(evt.proxy_nwk),
    }
    gid = evt.gpd_id
    if gid.app_id == 0:
        kwargs["application_id"] = ApplicationID.SrcID
        kwargs["src_id"] = SrcID(gid.src_id)
    else:
        kwargs["application_id"] = ApplicationID.IEEE
        kwargs["ieee"] = t.EUI64(gid.ieee)
        kwargs["endpoint"] = t.uint8_t(gid.endpoint)
    return t.ZigbeeGpPacket(**kwargs)


def record_from_device(dev: GreenPowerDevice) -> GpSinkRecord:
    """A zigpy GPD (e.g. from the EZSP era) as an ``R_GP_SINK`` record."""
    level = int(dev.security_level or 0)
    flags = (
        (GpSinkFlags.MAC_SEQ_CAPABLE if dev.mac_seq_num_capability else 0)
        | (GpSinkFlags.RX_ON_CAPABLE if dev.rx_on_capability else 0)
        | (GpSinkFlags.FIXED_LOCATION if dev.fixed_location else 0)
    )
    return GpSinkRecord(
        gpd_id=GpdId.srcid(int(dev.src_id)),
        device_id=int(dev.device_id or 0),
        communication_mode=2,
        group=GP_GROUP,
        assigned_alias=0xFFFF,
        flags=int(flags),
        security_level=level,
        key_type=int(dev.security_key_type or 0) if level else 0,
        key=dev.security_key.serialize() if dev.security_key is not None else None,
        frame_counter=int(dev.frame_counter or 0),
        groupcast_radius=0,
    )


def device_from_record(app: ControllerApplication, rec: GpSinkRecord) -> GreenPowerDevice:
    """A zigpy GPD from an NCP Sink Table entry."""
    from zigpy.zgp.types import DeviceID

    dev = GreenPowerDevice(app, application_id=ApplicationID.SrcID, src_id=SrcID(rec.gpd_id.src_id))
    dev.device_id = DeviceID(rec.device_id)
    dev.mac_seq_num_capability = bool(rec.flags & GpSinkFlags.MAC_SEQ_CAPABLE)
    dev.rx_on_capability = bool(rec.flags & GpSinkFlags.RX_ON_CAPABLE)
    dev.fixed_location = bool(rec.flags & GpSinkFlags.FIXED_LOCATION)
    level = SecurityLevel(rec.security_level & 0x03)
    dev.security_level = level
    dev.security_key_type = (
        SecurityKeyType(rec.key_type & 0x07)
        if level != SecurityLevel.NoSecurity
        else SecurityKeyType.NoKey
    )
    dev.security_key = t.KeyData(rec.key) if rec.key is not None else None
    dev.frame_counter = t.uint32_t(rec.frame_counter)
    return dev


class RadioSink:
    """The "sink on radio" delegate for the ``faronov/zigpy`` hook."""

    def __init__(self, bridge: GpBridge) -> None:
        self._bridge = bridge

    async def permit_join(self, time_s: int) -> None:
        await self._bridge.commissioning(time_s)

    async def unpair(self, device: GreenPowerDevice) -> None:
        await self._bridge.remove(int(device.src_id))


class GpBridge:
    def __init__(self, app: ControllerApplication, *, ncp_sink: bool, security_level: int) -> None:
        self.app = app
        self.ncp_sink = ncp_sink
        self.security_level = security_level
        self.hook = zigpy_has_radio_sink_hook()
        self.radio_sink = RadioSink(self)
        self.swallowed: list[tuple[str, t.ZigbeePacket]] = []
        self.window_until: float | None = None
        self._commissioning: dict[int, bytes] = {}
        self._tasks: set[asyncio.Task] = set()

    @property
    def api(self):
        return self.app._api

    # --- Configuration ----------------------------------------------------------

    async def configure(self) -> None:
        """``GP_SINK_CONFIG`` (zigpy profile, decision N1), sent at every start."""
        try:
            await self.api.request(
                m.GpSinkConfigReq(
                    mode=1 if self.ncp_sink else 0,
                    communication_mode=2,
                    group=GP_GROUP,
                    exit_mode=EXIT_MODE,
                    window_s=COMMISSIONING_WINDOW,
                    security_level=self.security_level,
                    groupcast_radius=0,
                )
            )
        except ZrhpError as e:
            if e.status != Status.UNSUPPORTED_COMMAND:
                raise
            LOGGER.info("NCP has no Green Power sink; GP is handled by zigpy")
            self.ncp_sink = False

    async def commissioning(self, time_s: int) -> None:
        if not self.ncp_sink:
            return
        loop = asyncio.get_running_loop()
        if time_s:
            req = m.GpSinkCommissioningReq(action=1, flags=0x01, window_s=time_s)
            self.window_until = loop.time() + time_s
        else:
            req = m.GpSinkCommissioningReq(action=0, flags=0, window_s=0)
            self.window_until = None
        try:
            await self.api.request(req)
        except ZrhpError as e:
            LOGGER.warning("GP commissioning %s failed: %s", "enter" if time_s else "exit", e)

    def window_remaining(self) -> int:
        if self.window_until is None:
            return 0
        return max(0, int(self.window_until - asyncio.get_running_loop().time()))

    async def remove(self, src_id: int) -> None:
        try:
            await self.api.request(
                m.GpSinkRemoveReq(gpd_id=GpdId.srcid(src_id), flags=0x01),
                allow=(Status.SUCCESS, Status.NOT_FOUND),
            )
        except ZrhpError as e:
            LOGGER.warning("GP_SINK_REMOVE of 0x%08X failed: %s", src_id, e)
        await self.app._store.gp_delete(gpd_key(GpdId.srcid(src_id)))

    # --- Swallowing (step 4) --------------------------------------------------

    def classify(self, packet: t.ZigbeePacket) -> str | None:
        """The sink transmission ``packet`` is, or ``None``."""
        if not self.ncp_sink:
            return None
        data = packet.data.serialize()
        if (
            packet.profile_id == GP_PROFILE
            and packet.cluster_id == GP_CLUSTER
            and packet.src_ep == GP_ENDPOINT
            and len(data) >= 3
            and data[0] & 0x08  # server -> client
            and not data[0] & 0x04
        ):
            return SINK_COMMANDS.get(data[2])
        if packet.profile_id == 0 and packet.cluster_id == 0x0013:
            # The sink's alias Device_annce of a GPD (A.3.6.3.4.2).
            if packet.alias_src is not None or data[3:11] == b"\xff" * 8:
                return "GPD alias Device_annce"
        return None

    async def swallow(self, kind: str, packet: t.ZigbeePacket) -> None:
        self.swallowed.append((kind, packet))
        LOGGER.debug("Not transmitting zigpy's %s: the NCP is the sink", kind)
        if kind == "GP Pairing":
            data = packet.data.serialize()
            # PairingOptions: bit3 add_sink, bit4 remove_gpd (A.3.3.5.2).
            if len(data) >= 10:
                options = int.from_bytes(data[3:6], "little")
                if options & 0x10 and options & 0x07 == 0:
                    src_id = int.from_bytes(data[6:10], "little")
                    await self.remove(src_id)

    # --- Events (step 3) --------------------------------------------------------

    def on_event(self, msg: m.Message, body: Any) -> None:
        if msg.msg_id == m.Id.EVT_GP_FRAME:
            self._on_frame(body)
        elif msg.msg_id == m.Id.EVT_GP_COMMISSIONED:
            self._spawn(self._on_commissioned(body))
        elif msg.msg_id == m.Id.EVT_GP_DECOMMISSIONED:
            self._spawn(self.app._store.gp_delete(gpd_key(body.gpd_id)))
        elif msg.msg_id == m.Id.EVT_GP_COMMISSIONING:
            if body.state == 0:
                self.window_until = None
        elif msg.msg_id == m.Id.EVT_GP_COMMISSIONING_FAILED:
            LOGGER.info("GP commissioning of %r failed: reason %d", body.gpd_id, body.reason)

    def _spawn(self, coro) -> None:
        task = asyncio.get_running_loop().create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _on_frame(self, evt: Any) -> None:
        if evt.result not in FED_RESULTS:
            return
        if evt.gpd_id.app_id == 0 and evt.command_id == 0xE0:
            self._commissioning[evt.gpd_id.src_id] = evt.payload
        try:
            packet = gp_packet_from_event(evt)
        except ValueError:
            LOGGER.warning("Cannot convert GP frame %r", evt)
            return
        self.app.gp_packet_received(packet)

    async def _on_commissioned(self, evt: Any) -> None:
        rec = evt.record
        if not isinstance(rec, GpSinkRecord):
            return
        await self.app._store.gp_put(gpd_key(rec.gpd_id), rec.serialize())
        if rec.gpd_id.app_id != 0:
            return
        # zigpy normally created the device from the commissioning frame; make
        # sure it exists even when its window was closed.
        await asyncio.sleep(0.5)
        ieee = synthetic_ieee(rec.gpd_id.src_id)
        if ieee in self.app.devices or self.app.green_power.get_pending_device(ieee):
            return
        self._adopt(rec)

    def _adopt(self, rec: GpSinkRecord) -> None:
        dev = device_from_record(self.app, rec)
        payload = self._commissioning.pop(rec.gpd_id.src_id, None)
        if payload is not None:
            try:
                from zigpy.zgp.commands import GPCommissioningPayload

                comm, _ = GPCommissioningPayload.deserialize(payload)
                dev.commands = [GPDCommandID(c) for c in comm.gpd_commands or []]
                dev.gpd_manufacturer_id = comm.manufacturer_id
                dev.gpd_model_id = comm.model_id
                dev.server_cluster_ids = list(comm.server_clusters or [])
                dev.client_cluster_ids = list(comm.client_clusters or [])
            except (ValueError, IndexError):
                pass
        LOGGER.info("Adopting GPD 0x%08X from the NCP sink table", rec.gpd_id.src_id)
        self.app.listener_event("device_joined", dev)
        self.app.device_initialized(dev)

    # --- Reconciliation (step 7) ------------------------------------------------

    async def read_sink_table(self) -> list[GpSinkRecord]:
        out: list[GpSinkRecord] = []
        start = 0
        while True:
            _, rsp = await self.api.request(m.GpSinkTableReadReq(start=start))
            recs = [r for r in rsp.records if isinstance(r, GpSinkRecord)]
            out += recs
            start += len(rsp.records)
            if not rsp.records or start >= rsp.total:
                return out

    async def reconcile(self) -> None:
        if not self.ncp_sink:
            return
        try:
            ncp = {r.gpd_id: r for r in await self.read_sink_table()}
        except ZrhpError as e:
            LOGGER.warning("Cannot read the NCP GP sink table: %s", e)
            return
        zigpy_gpds = {
            dev.src_id: dev
            for dev in self.app.devices.values()
            if isinstance(dev, GreenPowerDevice) and dev.src_id is not None
        }
        missing = [
            record_from_device(dev)
            for src, dev in zigpy_gpds.items()
            if GpdId.srcid(int(src)) not in ncp
        ]
        for i in range(0, len(missing), 8):
            chunk = missing[i : i + 8]
            try:
                _, rsp = await self.api.request(m.GpSinkTablePutReq(flags=0, records=chunk))
            except ZrhpError as e:
                LOGGER.warning("GP_SINK_TABLE_PUT failed: %s", e)
                break
            for rec, status in zip(chunk, rsp.statuses, strict=False):
                if status == Status.SUCCESS:
                    LOGGER.info("Imported GPD 0x%08X into the NCP sink", rec.gpd_id.src_id)
                    await self.app._store.gp_put(gpd_key(rec.gpd_id), rec.serialize())
                elif status != Status.ALREADY_EXISTS:
                    LOGGER.warning(
                        "NCP refused GPD 0x%08X: %s", rec.gpd_id.src_id, Status.from_int(status)
                    )
        for gid, rec in ncp.items():
            await self.app._store.gp_put(gpd_key(gid), rec.serialize())
            if gid.app_id == 0 and int(gid.src_id) not in zigpy_gpds:
                self._adopt(rec)

    async def shutdown(self) -> None:
        for task in list(self._tasks):
            task.cancel()
