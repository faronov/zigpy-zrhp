"""zigpy ``ControllerApplication`` for zigbee-rs NCPs over ZRHP (spec 12.1)."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from typing import Any

import zigpy.application
import zigpy.backups
import zigpy.config
import zigpy.device
import zigpy.exceptions
from zigpy.profiles import zgp as zgp_profile
import zigpy.state
import zigpy.types as t
import zigpy.util
import zigpy.zdo.types as zdo_t

from .. import __version__, messages as m
from ..api import LinkResetError, SessionInfo, SessionLost, ZrhpApi, ZrhpError
from ..config import (
    CONF_BAUDRATE_FALLBACK,
    CONF_CONFIRM_TIMEOUT,
    CONF_CONFIRM_TIMEOUT_EXTENDED,
    CONF_CONNECT_TIMEOUT,
    CONF_DEVICE_BAUDRATE,
    CONF_DEVICE_FLOW_CONTROL,
    CONF_DEVICE_PATH,
    CONF_GP_SECURITY_LEVEL,
    CONF_GP_SINK,
    CONF_LOCK_KEY_EXPORT,
    CONF_MANUFACTURER_CODE,
    CONF_RESUME_BUDGET,
    CONF_SIDECAR_PATH,
    CONF_TC_POLICY,
    CONF_USJ_RESET,
    CONF_ZRHP_CONFIG,
    CONFIG_SCHEMA,
    DEFAULT_BAUDRATE,
    FALLBACK_BAUDRATE,
    GP_SINK_NCP,
)
from ..gp import GP_ENDPOINT, GP_GROUP, GpBridge
from ..link import PeerChange
from ..ocb import (
    TCLK_DEFAULT,
    ieee_text,
    ieee_wire,
    ocb_to_records,
    passthrough_internal,
    records_to_ocb,
    restore_margins,
)
from ..records import (
    DeviceRecord,
    EndRecord,
    KeyAttrs,
    KeyOrigin,
    LinkBlock,
    RecordType,
    decode_records,
    encode_record,
    end_record,
    record_type_of,
)
from ..store import LinkKeyRow, SidecarStore, sidecar_path
from ..transport import ByteTransport, SerialTransport
from ..types import (
    FC_STRIDE,
    LOCK_CONFIRM,
    Capacity,
    IndicationFlags,
    NcpCaps,
    NetworkState,
    Status,
    TxOptions,
)
from ..zdo import LocalZdo
from .device import ZrhpCoordinator

LOGGER = logging.getLogger(__name__)

#: ``BKP_EXPORT_READ`` chunk.
EXPORT_CHUNK = 600
#: ``BKP_RESTORE_PUT`` payload budget (633 B message minus txn).
PUT_BUDGET = 600
APS_RETRY_DELAYS = (0.05, 0.1, 0.2, 0.4, 0.8, 1.0, 1.0, 1.0)
#: Keys of ``stack_specific`` the NCP holds itself (not passed through).
NCP_STACK_KEYS = ("zigbee_rs",)
APS_NO_ACK = 0xA7


class ControllerApplication(zigpy.application.ControllerApplication):
    SCHEMA = CONFIG_SCHEMA
    DISPLAY_NAME = "zigbee-rs NCP (ZRHP)"
    DESCRIPTION = "zigbee-rs network co-processor over USB-Serial-JTAG or UART"
    _watchdog_period = 30
    _probe_configs = [
        {CONF_DEVICE_BAUDRATE: DEFAULT_BAUDRATE, CONF_DEVICE_FLOW_CONTROL: None},
        {CONF_DEVICE_BAUDRATE: FALLBACK_BAUDRATE, CONF_DEVICE_FLOW_CONTROL: None},
    ]

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        zc = self._config[CONF_ZRHP_CONFIG]
        self._zrhp_config = zc
        self._api: ZrhpApi | None = None
        self._store: SidecarStore | None = None
        self._info: Any = None  # SysGetInfoRsp
        self._product: str | None = None
        self.host_endpoints: dict[int, zdo_t.SimpleDescriptor] = {}
        self._group_memberships: set[tuple[int, int]] = set()
        self._gp = GpBridge(
            self,
            ncp_sink=zc[CONF_GP_SINK] == GP_SINK_NCP,
            security_level=zc[CONF_GP_SECURITY_LEVEL],
        )
        self._zdo = LocalZdo(self)
        self._resumed = asyncio.Event()
        self._resumed.set()
        self._started = False
        self._resume_task: asyncio.Task | None = None
        self._budget_task: asyncio.Task | None = None
        self._reopen_task: asyncio.Task | None = None
        self._permit_until: float | None = None
        self._key_export_locked = False
        self._tx_power: float | None = None
        self._concentrator: tuple[int, int, int, int] | None = None
        self._last_counters = 0.0
        self._confirms: dict[int, asyncio.Future] = {}
        self._network_waiters: list[asyncio.Future] = []
        # The NCP holds one export transaction (a new BEGIN replaces it) and
        # one restore at a time.
        self._backup_lock = asyncio.Lock()
        self._scan_waiters: dict[int, asyncio.Future] = {}
        self.manufacturer_code = zc[CONF_MANUFACTURER_CODE] or 0x0000
        self._baudrate = self._config[zigpy.config.CONF_DEVICE][CONF_DEVICE_BAUDRATE]
        self._flow = self._config[zigpy.config.CONF_DEVICE][CONF_DEVICE_FLOW_CONTROL]
        self.backups.add_listener(self)

    # --- Hooks -------------------------------------------------------------------

    @property
    def gp_radio_sink(self):
        """The ``faronov/zigpy`` "sink on radio" hook (ignored by stock zigpy)."""
        return self._gp.radio_sink if self._gp.ncp_sink else None

    def _create_transport(self, baudrate: int, flow: str | None) -> ByteTransport:
        """The byte transport (overridden in tests to use the simulator)."""
        path = self._config[zigpy.config.CONF_DEVICE][CONF_DEVICE_PATH]
        return SerialTransport(path, baudrate, flow)

    @property
    def caps(self) -> NcpCaps:
        session = self._api.session if self._api is not None else None
        return session.caps if session is not None else NcpCaps(0)

    # --- connect / disconnect -------------------------------------------------

    async def connect(self) -> None:
        zc = self._zrhp_config
        attempts = [(self._baudrate, self._flow)]
        if zc[CONF_BAUDRATE_FALLBACK] and (self._baudrate, self._flow) != (FALLBACK_BAUDRATE, None):
            attempts.append((FALLBACK_BAUDRATE, None))
        store = self._store
        if store is None:
            path = zc[CONF_SIDECAR_PATH] or sidecar_path(
                self._config.get(zigpy.config.CONF_DATABASE)
            )
            store = SidecarStore(path)
            await store.open()
        last_exc: Exception | None = None
        try:
            for i, (baudrate, flow) in enumerate(attempts):
                api = ZrhpApi(
                    lambda b=baudrate, f=flow: self._create_transport(b, f),
                    name=f"zigpy-zrhp/{__version__}",
                    handshake_timeout=zc[CONF_CONNECT_TIMEOUT],
                )
                try:
                    # Only the configured rate earns a hard reset: a silent NCP
                    # there is more likely stuck than running at another rate.
                    await api.connect(reset_on_failure=(i == 0))
                except (SessionLost, OSError, ZrhpError) as e:
                    last_exc = e
                    LOGGER.debug("No ZRHP session at %s baud: %r", baudrate, e)
                    if api.handshake_rx_frames:
                        # Valid frames at this rate: the baud rate is right, the
                        # NCP just did not complete the handshake.
                        raise
                    continue
                self._baudrate, self._flow = baudrate, flow
                break
            else:
                raise last_exc or SessionLost("no ZRHP session")
            self._api = api
            self._store = store
            api.add_event_handler(self._on_event)
            api.add_session_handler(self._on_session)
            api.set_request_handler(self._on_ncp_request)
            _, self._info = await api.request(m.SysGetInfoReq())
            self._product = self._info.product.decode(errors="replace") or None
            await store.set_meta(last_ncp_cookie=api.session.ncp_cookie)
        except BaseException:
            if self._api is not None:
                await self._api.disconnect()
                self._api = None
            await store.close()
            self._store = None
            raise
        LOGGER.info(
            "Connected to %s (fw %s, chip %d, %s)",
            self._product,
            api.session.fw_version,
            api.session.negotiate.chip,
            "USB-Serial-JTAG" if self._info.transport == 1 else f"UART {self._info.uart_baud}",
        )

    async def disconnect(self) -> None:
        for task in (self._resume_task, self._budget_task, self._reopen_task):
            if task is not None and not task.done():
                task.cancel()
        await self._gp.shutdown()
        if self._api is not None:
            await self._api.disconnect()
            self._api = None
        if self._store is not None:
            await self._store.close()
            self._store = None
        self._started = False

    @property
    def api(self) -> ZrhpApi:
        if self._api is None:
            raise zigpy.exceptions.ControllerException("Not connected")
        return self._api

    # --- Network ----------------------------------------------------------------

    async def _get_info(self) -> Any:
        _, info = await self.api.request(m.NwkGetInfoReq())
        return info

    async def _bring_up(self) -> None:
        """``NWK_INIT`` with the checkpoint-log floors, then wait for ``up``."""
        assert self._store is not None
        session = self.api.session
        stride = session.capacity(Capacity.FC_STRIDE, FC_STRIDE) if session else FC_STRIDE
        nwk_floor, aps_floor = await self._store.floors(stride)
        loop = asyncio.get_running_loop()
        up: asyncio.Future = loop.create_future()
        self._network_waiters.append(up)
        try:
            status, rsp = await self.api.request(
                m.NwkInitReq(nwk_fc_floor=nwk_floor, aps_fc_floor=aps_floor),
                allow=(Status.SUCCESS, Status.NOT_FORMED),
            )
            if status == Status.NOT_FORMED:
                raise zigpy.exceptions.NetworkNotFormed("NCP has no network")
            async with asyncio.timeout(15):
                evt = await up
        finally:
            with contextlib.suppress(ValueError):
                self._network_waiters.remove(up)
        if evt.state != 2:
            raise zigpy.exceptions.FormationFailure(
                f"Network did not come up: reason {evt.reason}, zb_status 0x{evt.zb_status:02X}"
            )

    async def _ensure_up(self) -> Any:
        info = await self._get_info()
        if info.state == NetworkState.NONE:
            raise zigpy.exceptions.NetworkNotFormed("NCP has no network")
        if info.state != NetworkState.UP:
            await self._bring_up()
            info = await self._get_info()
        return info

    async def _tbl_sync(self) -> None:
        assert self._store is not None
        store = self._store
        _, rsp = await self.api.request(
            m.TblSyncReq(
                host_db_epoch=await store.meta("host_db_epoch", 0),
                last_ncp_table_epoch=await store.meta("table_epoch", 0),
                host_max_rev=await store.meta("host_max_rev", 0),
                flags=0,
            ),
            allow=(Status.SUCCESS, Status.UNSUPPORTED_COMMAND),
        )
        if rsp is not None:
            await store.set_meta(table_epoch=rsp.ncp_table_epoch)

    async def start_network(self) -> None:
        await self._ensure_up()
        if self.state.node_info.ieee in (None, t.EUI64.UNKNOWN):
            await self.load_network_info(load_devices=False)
        await self._tbl_sync()
        self.host_endpoints.clear()
        await self.register_endpoints()
        await self._replay_groups()
        await self._apply_tc_policy()
        if self._zrhp_config[CONF_MANUFACTURER_CODE] is not None:
            await self._optional(m.NwkSetManufacturerCodeReq(code=self.manufacturer_code))
        await self._gp.configure()
        await self._gp.reconcile()
        session = self.api.session
        assert session is not None
        inflight = session.capacity(Capacity.MAX_APS_INFLIGHT, 8)
        if inflight:
            self._concurrent_requests_semaphore.max_concurrency = inflight
        ieee = self.state.node_info.ieee
        self.devices[ieee] = ZrhpCoordinator(self, ieee, self.state.node_info.nwk)
        await self._device.schedule_initialize()
        self.state.node_info.model = self._device.model
        self.state.node_info.manufacturer = self._device.manufacturer
        self.state.node_info.version = session.fw_version
        self._started = True

    async def _optional(self, body: Any) -> Any:
        """A request the NCP may not implement yet (logged, not fatal)."""
        try:
            return await self.api.request(body)
        except ZrhpError as e:
            if e.status == Status.UNSUPPORTED_COMMAND:
                LOGGER.debug("NCP does not support %s", m.name_of(e.msg_id))
                return None
            raise

    async def _apply_tc_policy(self) -> None:
        p = self._zrhp_config[CONF_TC_POLICY]
        await self._optional(m.SecSetTcPolicyReq(**p))

    async def _replay_groups(self) -> None:
        memberships = set(self._group_memberships)
        for group in self.groups.values():
            for ieee, ep in group:
                if ieee == self.state.node_info.ieee:
                    memberships.add((group.group_id, ep))
        if not self._gp.ncp_sink and any(
            isinstance(d, zigpy.device.GreenPowerDevice) for d in self.devices.values()
        ):
            memberships.add((GP_GROUP, GP_ENDPOINT))
        for group_id, ep in sorted(memberships):
            await self._optional(m.NwkGroupMembershipReq(op=1, group=group_id, ep=ep))
        self._group_memberships = memberships

    async def force_remove(self, dev: zigpy.device.Device) -> None:
        if isinstance(dev, zigpy.device.GreenPowerDevice):
            await self._gp.remove(int(dev.src_id))
            return
        ieee = dev.ieee.serialize()
        await self._optional(m.NwkRemoveDeviceReq(nwk=dev.nwk, ieee=ieee, flags=0x02))
        await self._optional(m.TblInvalidateReq(table=RecordType.DEVICE, key=m.TableKey(1, ieee)))
        if self._store is not None:
            await self._store.delete_link_key(ieee)

    async def add_endpoint(self, descriptor: zdo_t.SimpleDescriptor) -> None:
        self.host_endpoints[descriptor.endpoint] = descriptor
        if descriptor.endpoint == GP_ENDPOINT:
            return  # the NCP owns the GP endpoint (proxy + sink)
        await self.api.request(
            m.NwkAddEndpointReq(
                ep=descriptor.endpoint,
                profile=descriptor.profile,
                device_id=descriptor.device_type,
                version=descriptor.device_version,
                in_clusters=list(descriptor.input_clusters)[:16],
                out_clusters=list(descriptor.output_clusters)[:16],
            )
        )

    def gp_endpoint_descriptor(self) -> zdo_t.SimpleDescriptor:
        return zdo_t.SimpleDescriptor(
            endpoint=GP_ENDPOINT,
            profile=zgp_profile.PROFILE_ID,
            device_type=zgp_profile.DeviceType.COMBO_BASIC,
            device_version=0,
            input_clusters=[0x0021],
            output_clusters=[0x0021],
        )

    async def permit_ncp(self, time_s: int = 60) -> None:
        await self.api.request(m.NwkPermitJoinReq(duration_s=time_s, target=0x0000, flags=0x01))
        loop = asyncio.get_running_loop()
        self._permit_until = loop.time() + time_s if time_s else None

    async def permit(self, time_s: int = 60, node: t.EUI64 | str | None = None) -> None:
        if node is not None:
            return await super().permit(time_s, node)
        assert 0 <= time_s <= 254
        await self.permit_gp(time_s)
        # The NCP broadcasts Mgmt_Permit_Joining_req itself and opens locally.
        await self.api.request(m.NwkPermitJoinReq(duration_s=time_s, target=0xFFFC, flags=0x01))
        loop = asyncio.get_running_loop()
        self._permit_until = loop.time() + time_s if time_s else None
        return None

    async def permit_gp(self, time_s: int) -> None:
        if not self._gp.hook:
            # Stock zigpy: open the NCP sink window here; zigpy's own GP
            # transmissions are swallowed in send_packet (7.11 step 2).
            await self._gp.commissioning(time_s)
        await super().permit_gp(time_s)

    async def permit_with_link_key(
        self, node: t.EUI64, link_key: t.KeyData, time_s: int = 60
    ) -> None:
        await self.api.request(
            m.SecAddLinkKeyReq(
                ieee=node.serialize(),
                key=link_key.serialize(),
                key_type=1,
                attrs=KeyAttrs.PROVISIONAL,
                rx_floor=0,
                flags=0x01,
            )
        )
        await self.permit(time_s)

    async def energy_scan(
        self, channels: t.Channels, duration_exp: int, count: int
    ) -> dict[int, float]:
        loop = asyncio.get_running_loop()
        result: asyncio.Future = loop.create_future()

        def on_sent(tid: int) -> None:
            self._scan_waiters[tid] = result

        try:
            await self.api.request_raw(
                m.Id.NWK_ENERGY_SCAN,
                m.NwkEnergyScanReq(
                    channel_mask=int(channels), duration_exp=duration_exp, count=count
                ).serialize(),
                on_sent=on_sent,
            )
            async with asyncio.timeout(
                10 + len(list(channels)) * count * (2**duration_exp) * 0.016
            ):
                evt = await result
        except (ZrhpError, TimeoutError) as e:
            LOGGER.warning("Energy scan failed: %r", e)
            return dict.fromkeys(channels, 0)
        finally:
            for k, v in list(self._scan_waiters.items()):
                if v is result:
                    del self._scan_waiters[k]
        return {r.channel: r.energy for r in evt.results}

    async def _move_network_to_channel(self, new_channel: int, new_nwk_update_id: int) -> None:
        await self.api.request(
            m.NwkChangeChannelReq(channel=new_channel, nwk_update_id=new_nwk_update_id)
        )

    async def _set_tx_power(self, tx_power: float) -> float | None:
        self._tx_power = tx_power
        rsp = await self._optional(m.NwkSetTxPowerReq(dbm=max(-128, min(127, round(tx_power)))))
        return None if rsp is None else rsp[1].applied_dbm

    async def _subscribe_to_multicast_group(self, group_id: t.Group, endpoint_id: int) -> None:
        if endpoint_id == GP_ENDPOINT and self._gp.ncp_sink:
            return  # the NCP sink owns the GP groupcast
        self._group_memberships.add((int(group_id), endpoint_id))
        await self._optional(m.NwkGroupMembershipReq(op=1, group=group_id, ep=endpoint_id))

    async def _unsubscribe_from_multicast_group(self, group_id: t.Group, endpoint_id: int) -> None:
        if endpoint_id == GP_ENDPOINT and self._gp.ncp_sink:
            return
        self._group_memberships.discard((int(group_id), endpoint_id))
        await self._optional(m.NwkGroupMembershipReq(op=2, group=group_id, ep=endpoint_id))

    async def _network_scan(self, channels: t.Channels, duration_exp: int):
        _, rsp = await self.api.request(
            m.NwkActiveScanReq(channel_mask=int(channels), duration_exp=duration_exp), timeout=60
        )
        for r in rsp.results:
            yield t.NetworkBeacon(
                pan_id=t.PanId(r.pan),
                extended_pan_id=t.ExtendedPanId(r.epid),
                channel=r.channel,
                permit_joining=bool(r.permit),
                stack_profile=r.stack_profile,
                nwk_update_id=r.update_id,
                lqi=r.lqi,
                src=t.NWK(r.src),
                rssi=r.rssi,
                depth=None,
                router_capacity=None,
                device_capacity=None,
                protocol_version=None,
            )

    async def _watchdog_feed(self) -> None:
        budget = self._zrhp_config[CONF_RESUME_BUDGET]
        async with asyncio.timeout(budget + 5):
            await self._resumed.wait()
        await self.api.request(m.SysEchoReq(data=b"zigpy"), wait_session=budget)
        now = time.monotonic()
        if now - self._last_counters >= 30:
            self._last_counters = now
            with contextlib.suppress(ZrhpError):
                await self._update_counters()

    async def _update_counters(self) -> None:
        from ..link import COUNTER_NAMES

        _, rsp = await self.api.request(m.DiagGetCountersReq(group_mask=0xFF))
        group = self.state.counters["zrhp_ncp"]
        for c in rsp.counters:
            group[COUNTER_NAMES.get(c.id, f"0x{c.id:04X}")].update(c.value)
        host = self.state.counters["zrhp_host"]
        if self.api.driver is not None:
            for k, v in self.api.driver.counters().items():
                host[k].update(v)
        for k, v in self.api.counters.items():
            host[k].update(v)

    # --- Network info / backups -------------------------------------------------

    async def _export(self, *, keys: bool, devices: bool, gp: bool) -> list[Any]:
        async with self._backup_lock:
            return await self._export_locked(keys=keys, devices=devices, gp=gp)

    async def _export_locked(self, *, keys: bool, devices: bool, gp: bool) -> list[Any]:
        flags = (0x01 if keys else 0) | (0x02 if devices else 0) | (0x04 if gp else 0)
        _, begin = await self.api.request(m.BkpExportBeginReq(flags=flags))
        stream = bytearray()
        try:
            while True:
                status, rsp = await self.api.request(
                    m.BkpExportReadReq(txn=begin.txn, max_bytes=EXPORT_CHUNK), timeout=10
                )
                stream += rsp.records
                if not rsp.more:
                    break
        finally:
            with contextlib.suppress(ZrhpError):
                await self.api.request(m.BkpExportEndReq(txn=begin.txn))
        return decode_records(bytes(stream))

    async def load_network_info(self, *, load_devices: bool = False) -> None:
        info = await self._get_info()
        if info.state == NetworkState.NONE:
            raise zigpy.exceptions.NetworkNotFormed("NCP has no network")
        if info.state != NetworkState.UP:
            await self._bring_up()
        records = await self._export(keys=True, devices=load_devices, gp=load_devices)
        records = await self._merge_host_keys(records)
        assert self._store is not None
        passthrough = await self._store.meta("passthrough", {})
        ocb = records_to_ocb(
            records,
            source=f"zigpy-zrhp@{__version__}",
            creation_time=_now_iso(),
            passthrough_stack_specific=passthrough.get("stack_specific", {}),
            passthrough_internal=passthrough.get("internal", {}),
        )
        backup = zigpy.backups.NetworkBackup.from_open_coordinator_json(ocb)
        network_info = backup.network_info
        node_info = backup.node_info
        keys_present = any(record_type_of(r) == RecordType.NETWORK_KEY for r in records)
        if not keys_present:
            LOGGER.warning("Key export is locked or unsupported: the backup is incomplete")
            network_info = network_info.replace(network_key=zigpy.state.Key(key=t.KeyData.UNKNOWN))
        session = self.api.session
        network_info = network_info.replace(
            source=f"zigpy-zrhp@{__version__}",
            metadata={
                **network_info.metadata,
                "zigbee_rs": {
                    "fw": session.fw_version,
                    "chip": session.negotiate.chip,
                    "build_id": session.negotiate.build_id.hex(),
                },
            },
            nwk_manager_id=t.NWK(info.nwk_manager),
            tx_power=info.tx_power if info.tx_power != 0x7F else network_info.tx_power,
        )
        node_info = node_info.replace(
            model=self._product or "ZRHP NCP",
            manufacturer="zigbee-rs",
            version=session.fw_version,
        )
        self.state.network_info = network_info
        self.state.node_info = node_info

    async def _merge_host_keys(self, records: list[Any]) -> list[Any]:
        """Fill keys the NCP does not cache (paging) from the host store (9.5)."""
        assert self._store is not None
        host = {r.ieee: r for r in await self._store.all_link_keys() if r.key is not None}
        if not host:
            return records
        body = [r for r in records if not isinstance(r, EndRecord)]
        aps_limit = next(
            (r.tx_counter for r in body if r.__class__.__name__ == "TcLinkKeyRecord"), 0
        )
        seen = set()
        out = []
        for r in body:
            if isinstance(r, DeviceRecord):
                seen.add(r.ieee)
                h = host.get(r.ieee)
                if r.link is None and h is not None:
                    r = r.replace(link=_link_block(h, aps_limit))
            out.append(r)
        for ieee, h in host.items():
            if ieee not in seen:
                out.append(
                    DeviceRecord(
                        ieee=ieee,
                        nwk=h.nwk if h.nwk is not None else 0xFFFF,
                        flags=0x08 if h.nwk is not None else 0,
                        link=_link_block(h, aps_limit),
                    )
                )
        return [*out, end_record([encode_record(r) for r in out])]

    async def can_write_network_settings(
        self, *, network_info: zigpy.state.NetworkInfo, node_info: zigpy.state.NodeInfo
    ) -> bool:
        active = t.EUI64(self._info.ieee_active)
        wanted = node_info.ieee
        if wanted not in (t.EUI64.UNKNOWN, active) and not self.caps & NcpCaps.IEEE_REWRITABLE:
            raise zigpy.exceptions.CannotWriteNetworkSettings(
                f"The NCP cannot change its IEEE address to {wanted}"
            )
        if not self.caps & NcpCaps.BACKUP_RESTORE:
            raise zigpy.exceptions.CannotWriteNetworkSettings(
                "The NCP firmware cannot restore backups"
            )
        return True

    async def write_network_info(
        self, *, network_info: zigpy.state.NetworkInfo, node_info: zigpy.state.NodeInfo
    ) -> None:
        network_info, node_info = _normalize(network_info, node_info)
        await self.can_write_network_settings(network_info=network_info, node_info=node_info)
        assert self._store is not None
        active = t.EUI64(self._info.ieee_active)
        if node_info.ieee == t.EUI64.UNKNOWN:
            node_info = node_info.replace(ieee=active)
        tc = network_info.tc_link_key
        if tc.partner_ieee in (t.EUI64.UNKNOWN, t.EUI64.convert("00:00:00:00:00:00:00:00")):
            network_info = network_info.replace(tc_link_key=tc.replace(partner_ieee=node_info.ieee))
        if tc.key is None:
            network_info = network_info.replace(
                tc_link_key=network_info.tc_link_key.replace(key=t.KeyData(TCLK_DEFAULT))
            )
        ocb = zigpy.backups.NetworkBackup(
            network_info=network_info, node_info=node_info
        ).as_open_coordinator_json()
        ieee_change = node_info.ieee != active
        records = ocb_to_records(ocb, node_flags=0x01 if ieee_change else 0x00)
        _, aps_margin = restore_margins(ocb)
        if _counters_unknown(network_info):
            aps_margin = 1 << 20
        # Rule 3: the host stores every DEVICE record before COMMIT.
        await self._store.clear_network()
        rows = [
            LinkKeyRow(
                ieee=r.ieee,
                key=r.link.key,
                attrs=r.link.attrs,
                origin=r.link.origin,
                key_seq=r.link.key_seq,
                rx_floor=r.link.rx_floor,
                nwk=r.nwk if r.nwk_valid else None,
            )
            for r in records
            if isinstance(r, DeviceRecord) and r.link is not None
        ]
        await self._store.upsert_link_keys(rows)
        passthrough = {
            "stack_specific": {
                k: v
                for k, v in (network_info.stack_specific or {}).items()
                if k not in NCP_STACK_KEYS and k != "form_quickly"
            },
            "internal": passthrough_internal(ocb),
        }
        # zigpy keeps ezsp.hashed_tclk in stack_specific; the NCP stores the seed
        # and it comes back as a record, so drop the duplicate.
        ezsp = dict(passthrough["stack_specific"].get("ezsp", {}))
        ezsp.pop("hashed_tclk", None)
        if ezsp:
            passthrough["stack_specific"]["ezsp"] = ezsp
        else:
            passthrough["stack_specific"].pop("ezsp", None)
        await self._store.set_meta(passthrough=passthrough)

        info = await self._get_info()
        if info.state == NetworkState.UP:
            # The NCP restores only with the stack stopped; the wipe keeps the
            # frame-counter bounds, the IEEE override and the endpoints.
            await self.api.request(m.NwkLeaveResetReq(flags=0x03), timeout=15)
        await self._restore(records, nwk_margin=0, aps_margin=aps_margin, allow_ieee=ieee_change)
        self.state.network_info = network_info
        self.state.node_info = node_info

    async def _restore(
        self, records: list[Any], *, nwk_margin: int, aps_margin: int, allow_ieee: bool
    ) -> Any:
        session = self.api.session
        max_per_put = session.capacity(Capacity.MAX_RESTORE_RECORDS_PER_PUT, 16) or 16
        _, begin = await self.api.request(
            m.BkpRestoreBeginReq(
                flags=0x01 if allow_ieee else 0x00,
                nwk_margin=nwk_margin,
                aps_margin=aps_margin,
                expected_records=len(records),
            )
        )
        try:
            tlvs = [encode_record(r) for r in records]
            chunk: list[bytes] = []
            per_put = min(max_per_put, begin.max_records_per_put or max_per_put)

            async def put(chunk: list[bytes]) -> None:
                _, rsp = await self.api.request(
                    m.BkpRestorePutReq(txn=begin.txn, records=b"".join(chunk)), timeout=10
                )
                for note in rsp.notes:
                    LOGGER.info("Restore note for record %d: %d", note.index, note.note)

            for tlv in tlvs:
                if chunk and (
                    len(chunk) >= per_put or sum(map(len, chunk)) + len(tlv) > PUT_BUDGET
                ):
                    await put(chunk)
                    chunk = []
                chunk.append(tlv)
            if chunk:
                await put(chunk)
            _, commit = await self.api.request(m.BkpRestoreCommitReq(txn=begin.txn), timeout=30)
        except BaseException:
            with contextlib.suppress(Exception):
                await self.api.request(m.BkpRestoreAbortReq(txn=begin.txn))
            raise
        LOGGER.info(
            "Restored: NWK counter %d, APS counter %d, %d keys, %d children",
            commit.nwk_fc_start,
            commit.aps_fc_start,
            commit.link_keys_on_ncp,
            commit.children,
        )
        assert self._store is not None
        await self._store.add_checkpoint(1, 0, commit.nwk_fc_start, 0)
        await self._store.add_checkpoint(2, 0, commit.aps_fc_start, 0)
        return commit

    async def reset_network_info(self) -> None:
        await self.api.request(m.NwkLeaveResetReq(flags=0x00), timeout=15)
        if self._store is not None:
            await self._store.clear_network()
        self._started = False

    def network_backup_created(self, backup: zigpy.backups.NetworkBackup) -> None:
        """BackupManager listener: optionally lock key export after a backup."""
        if self._zrhp_config[CONF_LOCK_KEY_EXPORT] and self._api is not None:
            self.create_task(self._lock_key_export(), "zrhp_lock_key_export")

    def network_backup_removed(self, backup: zigpy.backups.NetworkBackup) -> None:
        pass

    async def _lock_key_export(self) -> None:
        await self.api.request(m.SecLockKeyExportReq(confirm=LOCK_CONFIRM))
        self._key_export_locked = True

    # --- Data -------------------------------------------------------------------

    async def send_packet(self, packet: t.ZigbeePacket) -> None:
        LOGGER.debug("Sending packet %r", packet)
        if self._zdo.is_local(packet):
            await self._send_local_zdo(packet)
            return
        kind = self._gp.classify(packet)
        if kind is not None:
            await self._gp.swallow(kind, packet)
            return
        budget = self._zrhp_config[CONF_RESUME_BUDGET]
        try:
            async with asyncio.timeout(budget):
                await self._resumed.wait()
        except TimeoutError:
            raise zigpy.exceptions.DeliveryError("NCP is not available") from None
        req = self._aps_request(packet)
        async with self._limit_concurrency(priority=packet.priority):
            await self._send_aps(req, packet)

    def _aps_request(self, packet: t.ZigbeePacket) -> m.ApsDataRequest:
        dst = packet.dst
        assert dst is not None
        if dst.addr_mode == t.AddrMode.IEEE:
            mode, address = m.AddrMode.IEEE, dst.address.serialize()
        elif dst.addr_mode == t.AddrMode.Group:
            mode, address = m.AddrMode.GROUP, int(dst.address)
        elif dst.addr_mode == t.AddrMode.Broadcast:
            mode, address = m.AddrMode.BROADCAST, int(dst.address)
        else:
            mode, address = m.AddrMode.NWK, int(dst.address)
        opts = TxOptions.NONE
        if t.TransmitOptions.ACK in packet.tx_options and mode in (m.AddrMode.NWK, m.AddrMode.IEEE):
            opts |= TxOptions.APS_ACK
        if t.TransmitOptions.APS_Encryption in packet.tx_options:
            opts |= TxOptions.APS_SECURITY
        if t.TransmitOptions.FORCE_ROUTE_DISCOVERY in packet.tx_options:
            opts |= TxOptions.FORCE_ROUTE_DISCOVERY
        if packet.extended_timeout:
            opts |= TxOptions.EXTENDED_TIMEOUT
        data = packet.data.serialize()
        session = self.api.session
        max_asdu = session.capacity(Capacity.MAX_ASDU, 100) if session else 100
        if len(data) > max_asdu and self.caps & NcpCaps.APS_FRAGMENTATION:
            opts |= TxOptions.FRAGMENTATION
        relays = None
        if packet.source_route is not None and self.caps & NcpCaps.HOST_SOURCE_ROUTES:
            limit = session.capacity(Capacity.MAX_SOURCE_ROUTE_RELAYS, 8) if session else 8
            if len(packet.source_route) <= limit:
                relays = [int(r) for r in packet.source_route]
        alias = None
        if packet.alias_src is not None:
            alias = (int(packet.alias_src), int(packet.alias_seq or 0))
        priority = 1 if packet.priority is None else max(0, min(3, int(packet.priority) + 1))
        return m.ApsDataRequest(
            dst_mode=mode,
            dst=address,
            dst_ep=int(packet.dst_ep or 0),
            src_ep=int(packet.src_ep or 0),
            profile=int(packet.profile_id),
            cluster=int(packet.cluster_id),
            tx_options=int(opts),
            radius=int(packet.radius or 0),
            non_member_radius=int(packet.non_member_radius or 0),
            priority=priority,
            relays=relays,
            alias=alias,
            asdu=data,
        )

    async def _send_aps(self, req: m.ApsDataRequest, packet: t.ZigbeePacket) -> None:
        loop = asyncio.get_running_loop()
        zc = self._zrhp_config
        confirm_timeout = zc[
            CONF_CONFIRM_TIMEOUT_EXTENDED if packet.extended_timeout else CONF_CONFIRM_TIMEOUT
        ]
        payload = req.serialize()
        for delay in (*APS_RETRY_DELAYS, None):
            confirm: asyncio.Future = loop.create_future()
            tids: list[int] = []

            def on_sent(tid: int, confirm=confirm, tids=tids) -> None:
                tids.append(tid)
                self._confirms[tid] = confirm

            tid_holder = tids
            try:
                raw = await self.api.request_raw(
                    m.Id.APS_DATA_REQUEST, payload, on_sent=on_sent, retry=True
                )
            except LinkResetError as e:
                self._drop_confirm(tid_holder)
                raise zigpy.exceptions.DeliveryError(
                    "NCP restarted, delivery unknown", status=t.MACStatus.MAC_CHANNEL_ACCESS_FAILURE
                ) from e
            except (ZrhpError, SessionLost) as e:
                self._drop_confirm(tid_holder)
                raise zigpy.exceptions.DeliveryError(f"APS request failed: {e}") from e
            status = Status.from_int(raw[0])
            if status == Status.BUSY and delay is not None:
                self._drop_confirm(tid_holder)
                await asyncio.sleep(delay)
                continue
            if status != Status.SUCCESS:
                self._drop_confirm(tid_holder)
                raise zigpy.exceptions.DeliveryError(f"NCP refused the APS request: {status!r}")
            try:
                async with asyncio.timeout(confirm_timeout):
                    evt = await confirm
            except TimeoutError:
                raise zigpy.exceptions.DeliveryError(
                    "No APS confirm from the NCP", status=APS_NO_ACK
                ) from None
            finally:
                self._drop_confirm(tid_holder)
            if evt.status != 0:
                raise zigpy.exceptions.DeliveryError(
                    f"Failed to deliver packet: zb_status 0x{evt.zb_status:02X}",
                    status=evt.zb_status,
                )
            return
        raise zigpy.exceptions.DeliveryError("NCP APS queue stayed busy")

    def _drop_confirm(self, tids: list[int]) -> None:
        for tid in tids:
            self._confirms.pop(tid, None)

    async def _send_local_zdo(self, packet: t.ZigbeePacket) -> None:
        try:
            rsp = await self._zdo.handle(packet)
        except (ZrhpError, ValueError) as e:
            raise zigpy.exceptions.DeliveryError(f"Local ZDO request failed: {e}") from e
        if rsp is None:
            return
        node = self.state.node_info
        response = t.ZigbeePacket(
            src=t.AddrModeAddress(addr_mode=t.AddrMode.NWK, address=node.nwk),
            src_ep=0,
            dst=t.AddrModeAddress(addr_mode=t.AddrMode.NWK, address=node.nwk),
            dst_ep=0,
            tsn=rsp[0],
            profile_id=0,
            cluster_id=packet.cluster_id | 0x8000,
            data=t.SerializableBytes(rsp),
            lqi=255,
            rssi=0,
        )
        asyncio.get_running_loop().call_soon(self.packet_received, response)

    # --- Events -------------------------------------------------------------------

    def _on_event(self, msg: m.Message, body: Any) -> None:
        mid = msg.msg_id
        if mid == m.Id.EVT_APS_DATA_INDICATION:
            self._on_indication(body)
        elif mid == m.Id.EVT_APS_DATA_CONFIRM:
            fut = self._confirms.pop(body.req_tid, None)
            if fut is not None and not fut.done():
                fut.set_result(body)
        elif mid == m.Id.EVT_DEVICE_JOINED:
            if body.decision == 0:
                self.handle_join(t.NWK(body.nwk), t.EUI64(body.ieee), t.NWK(body.parent_nwk))
            else:
                LOGGER.warning("NCP denied the join of %s", t.EUI64(body.ieee))
        elif mid == m.Id.EVT_DEVICE_LEFT:
            ieee = t.EUI64(body.ieee)
            if body.ieee == bytes(8):
                with contextlib.suppress(KeyError):
                    ieee = self.get_device(nwk=body.nwk).ieee
            self.handle_leave(t.NWK(body.nwk), ieee)
        elif mid == m.Id.EVT_ADDRESS_CHANGED:
            self.handle_join(t.NWK(body.new_nwk), t.EUI64(body.ieee), None, handle_rejoin=False)
        elif mid == m.Id.EVT_ROUTE_RECORD:
            self.handle_relays(t.NWK(body.src_nwk), [t.NWK(r) for r in body.relays])
        elif mid == m.Id.EVT_FC_CHECKPOINT:
            if self._store is not None:
                self.create_task(
                    self._store.add_checkpoint(
                        body.domain, body.key_seq, body.durable_limit, body.generation
                    ),
                    "zrhp_fc_checkpoint",
                )
        elif mid == m.Id.EVT_TBL_EPOCH_CHANGED:
            if self._store is not None:
                self.create_task(self._store.set_meta(table_epoch=body.new_epoch), "zrhp_epoch")
        elif mid == m.Id.EVT_NETWORK_STATE:
            for fut in list(self._network_waiters):
                if not fut.done():
                    fut.set_result(body)
            if body.state == 0 and self._started and body.req_tid == 0:
                LOGGER.warning("NCP network went down (reason %d)", body.reason)
        elif mid == m.Id.EVT_ENERGY_SCAN_RESULT:
            fut = self._scan_waiters.pop(body.req_tid, None)
            if fut is not None and not fut.done():
                fut.set_result(body)
        elif mid == m.Id.EVT_CHANNEL_CHANGED:
            self.state.network_info = self.state.network_info.replace(
                channel=body.channel, nwk_update_id=body.nwk_update_id
            )
        elif mid == m.Id.EVT_PERMIT_JOIN_STATE:
            loop = asyncio.get_running_loop()
            self._permit_until = loop.time() + body.remaining_s if body.remaining_s else None
        elif mid == m.Id.EVT_KEY_FAILURE:
            LOGGER.warning("Key failure for %s: reason %d", t.EUI64(body.ieee), body.reason)
        elif mid == m.Id.EVT_LOG_RECORD:
            LOGGER.debug(
                "NCP log [%d/%d]: %s", body.level, body.module, body.text.decode(errors="replace")
            )
        elif mid == m.Id.EVT_INDICATIONS_DROPPED:
            LOGGER.warning("NCP dropped %d indications (reason %d)", body.count, body.reason)
        elif mid == m.Id.EVT_FATAL:
            LOGGER.error(
                "NCP fatal error %d/0x%08X: %s",
                body.kind,
                body.code,
                body.text.decode(errors="replace"),
            )
        elif 0x0A80 <= mid <= 0x0AFF:
            self._gp.on_event(msg, body)

    def _on_indication(self, ind: Any) -> None:
        flags = IndicationFlags(ind.flags)
        if IndicationFlags.HANDLED_BY_NCP in flags and ind.profile == 0 and ind.cluster < 0x8000:
            return  # the NCP already answered this ZDO request
        if ind.dst_mode == 0x01:
            dst = t.AddrModeAddress(addr_mode=t.AddrMode.Group, address=t.Group(ind.dst))
        elif ind.dst_mode == 0x0F:
            dst = t.AddrModeAddress(
                addr_mode=t.AddrMode.Broadcast, address=t.BroadcastAddress(ind.dst)
            )
        else:
            dst = t.AddrModeAddress(addr_mode=t.AddrMode.NWK, address=self.state.node_info.nwk)
        self.packet_received(
            t.ZigbeePacket(
                src=t.AddrModeAddress(addr_mode=t.AddrMode.NWK, address=t.NWK(ind.src_nwk)),
                src_ep=ind.src_ep,
                dst=dst,
                dst_ep=ind.dst_ep,
                tsn=_tsn(ind.profile, ind.asdu),
                profile_id=ind.profile,
                cluster_id=ind.cluster,
                data=t.SerializableBytes(ind.asdu),
                lqi=ind.lqi,
                rssi=None if ind.rssi == -128 else ind.rssi,
            )
        )

    async def _on_ncp_request(self, msg: m.Message, body: Any) -> bytes:
        """``TBL_LOOKUP`` / ``TBL_WRITEBACK`` from the NCP (spec 8.5)."""
        assert self._store is not None
        if msg.msg_id == m.Id.TBL_WRITEBACK:
            rec = body.record
            if not isinstance(rec, DeviceRecord):
                return bytes([Status.SUCCESS])  # other tables: nothing to persist yet
            link = rec.link
            row = LinkKeyRow(
                ieee=rec.ieee,
                key=link.key if link else None,
                attrs=link.attrs if link else KeyAttrs.VERIFIED,
                origin=link.origin if link else KeyOrigin.TC_GENERATED,
                key_seq=link.key_seq if link else 0,
                rx_floor=link.rx_floor if link else 0,
                rev=body.rev,
                nwk=rec.nwk if rec.nwk_valid else None,
            )
            if body.reason == 4:  # DELETE
                await self._store.delete_link_key(rec.ieee)
            else:
                await self._store.upsert_link_key(row)
            return bytes([Status.SUCCESS])
        if msg.msg_id == m.Id.TBL_LOOKUP:
            key = body.key
            if key.key_type == 1:
                row = await self._store.get_link_key(ieee=key.key)
            else:
                row = await self._store.get_link_key(nwk=key.key)
                if row is None:
                    with contextlib.suppress(KeyError):
                        dev = self.get_device(nwk=key.key)
                        row = await self._store.get_link_key(ieee=dev.ieee.serialize())
            if row is None or row.key is None:
                return bytes([Status.NOT_FOUND])
            aps = await self._store.last_limit(2)
            rec = DeviceRecord(
                ieee=row.ieee,
                nwk=row.nwk if row.nwk is not None else 0xFFFF,
                flags=0x08 if row.nwk is not None else 0,
                link=_link_block(row, aps),
            )
            return m.encode_response(m.TblLookupRsp(rev=row.rev, record=rec))
        return bytes([Status.UNSUPPORTED_COMMAND])

    # --- Seamless resume (spec 12.1) --------------------------------------------

    def _on_session(self, state: str, info: SessionInfo | None) -> None:
        if not self._started:
            return
        if state in ("lost", "port_lost"):
            if self._resumed.is_set():
                LOGGER.warning(
                    "NCP session lost; holding requests (budget %ss)",
                    self._zrhp_config[CONF_RESUME_BUDGET],
                )
                self._resumed.clear()
                self._budget_task = self.create_task(self._resume_budget(), "zrhp_resume_budget")
            if state == "port_lost" and (self._reopen_task is None or self._reopen_task.done()):
                self._reopen_task = self.create_task(self._reopen_port(), "zrhp_reopen")
        elif state == "ready" and info is not None:
            if self._resume_task is not None and not self._resume_task.done():
                self._resume_task.cancel()
            self._resume_task = self.create_task(self._resume(info), "zrhp_resume")

    async def _reopen_port(self) -> None:
        while not self.api.is_ready:
            try:
                await self.api.reopen()
                return
            except OSError as e:
                LOGGER.debug("Port not back yet: %r", e)
                await asyncio.sleep(1.0)

    async def _resume_budget(self) -> None:
        budget = self._zrhp_config[CONF_RESUME_BUDGET]
        try:
            async with asyncio.timeout(budget):
                await self._resumed.wait()
                return
        except TimeoutError:
            pass
        if self._zrhp_config[CONF_USJ_RESET]:
            LOGGER.warning("NCP did not come back within %ss, trying a DTR/RTS hard reset", budget)
            with contextlib.suppress(Exception):
                await self.api.hard_reset()
            try:
                async with asyncio.timeout(budget):
                    await self._resumed.wait()
                    return
            except TimeoutError:
                pass
        self._give_up(SessionLost(f"NCP did not resume within {budget}s"))

    def _give_up(self, exc: Exception) -> None:
        LOGGER.error("Cannot resume the NCP session: %s", exc)
        self._started = False
        self.connection_lost(exc)

    async def _resume(self, info: SessionInfo) -> None:
        try:
            if info.change is PeerChange.RESTARTED:
                await self._reconcile(info)
            else:
                ready = await self._get_info()
                if ready.state != NetworkState.UP:
                    await self._reconcile(info)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self._give_up(e)
            return
        self.state.counters["zrhp"]["ncp_resumed"].increment()
        LOGGER.info("NCP session resumed (%s)", info.change.value)
        self._resumed.set()

    async def _reconcile(self, info: SessionInfo) -> None:
        assert self._store is not None
        ready = info.ready
        if ready.network_state == NetworkState.NONE:
            raise SessionLost("the NCP lost its network")
        epoch = await self._store.meta("table_epoch")
        if epoch is not None and ready.table_epoch != epoch:
            raise SessionLost(f"NCP table epoch changed ({epoch} -> {ready.table_epoch})")
        if ready.network_state != NetworkState.UP:
            # The NCP only reports the network parameters once NWK_INIT has
            # brought the persisted network up (formed-down reads back as an
            # unconfigured NIB), so start it before comparing.
            await self._bring_up()
        net = await self._get_info()
        ni = self.state.network_info
        node = self.state.node_info
        mismatch = [
            name
            for name, ok in (
                ("ieee", t.EUI64(net.ieee) == node.ieee),
                ("pan_id", net.pan_id == ni.pan_id),
                ("epid", t.ExtendedPanId(net.ext_pan_id) == ni.extended_pan_id),
                ("security_level", net.security_level == ni.security_level),
                ("nwk_update_id", _seq_ge(net.nwk_update_id, ni.nwk_update_id)),
                ("key_seq", _seq_ge(net.key_seq, ni.network_key.seq or 0)),
            )
            if not ok
        ]
        if mismatch:
            raise SessionLost(f"NCP network differs after restart: {', '.join(mismatch)}")
        if net.channel != ni.channel and net.nwk_update_id == ni.nwk_update_id:
            raise SessionLost("NCP channel changed without an update ID change")
        if (
            net.nwk_update_id != ni.nwk_update_id
            or net.channel != ni.channel
            or net.key_seq != (ni.network_key.seq or 0)
        ):
            # A rotation or channel change completed during the outage.
            self.state.network_info = ni.replace(
                channel=net.channel,
                nwk_update_id=net.nwk_update_id,
                network_key=ni.network_key.replace(seq=net.key_seq),
            )
        _, self._info = await self.api.request(m.SysGetInfoReq())
        await self._apply_tc_policy()
        for desc in list(self.host_endpoints.values()):
            await self.add_endpoint(desc)
        await self._replay_groups()
        if self._tx_power is not None:
            await self._set_tx_power(self._tx_power)
        if self._zrhp_config[CONF_MANUFACTURER_CODE] is not None:
            await self._optional(m.NwkSetManufacturerCodeReq(code=self.manufacturer_code))
        await self._gp.configure()
        loop = asyncio.get_running_loop()
        if self._permit_until is not None:
            remaining = int(self._permit_until - loop.time())
            if remaining > 0:
                await self.api.request(
                    m.NwkPermitJoinReq(duration_s=min(254, remaining), target=0xFFFC, flags=1)
                )
        gp_remaining = self._gp.window_remaining()
        if gp_remaining > 0:
            await self._gp.commissioning(gp_remaining)
        if self._key_export_locked:
            await self.api.request(m.SecLockKeyExportReq(confirm=LOCK_CONFIRM))
        await self._tbl_sync()
        await self._gp.reconcile()


def _normalize(
    ni: zigpy.state.NetworkInfo, node: zigpy.state.NodeInfo
) -> tuple[zigpy.state.NetworkInfo, zigpy.state.NodeInfo]:
    """zigpy fills some fields with plain ints (``form_network``)."""
    node = node.replace(nwk=t.NWK(node.nwk), ieee=t.EUI64(node.ieee))
    ni = ni.replace(
        pan_id=t.PanId(ni.pan_id),
        extended_pan_id=t.ExtendedPanId(ni.extended_pan_id),
        nwk_manager_id=t.NWK(ni.nwk_manager_id),
        nwk_update_id=t.uint8_t(ni.nwk_update_id),
        channel=t.uint8_t(ni.channel),
        channel_mask=t.Channels(ni.channel_mask),
    )
    return ni, node


def _seq_ge(a: int, b: int) -> bool:
    """``a >= b`` for 8-bit sequence numbers with wrap."""
    return ((a - b) & 0xFF) < 0x80


def _tsn(profile: int, asdu: bytes) -> int:
    if not asdu:
        return 0
    if profile == 0:
        return asdu[0]
    if len(asdu) >= 2 and asdu[0] & 0x04:  # manufacturer-specific ZCL header
        return asdu[3] if len(asdu) >= 4 else 0
    return asdu[1] if len(asdu) >= 2 else 0


def _link_block(row: LinkKeyRow, aps_limit: int) -> LinkBlock:
    return LinkBlock(
        key=row.key,
        key_seq=row.key_seq,
        attrs=row.attrs,
        origin=row.origin,
        tx_counter=aps_limit,
        rx_floor=row.rx_floor,
    )


def _counters_unknown(ni: zigpy.state.NetworkInfo) -> bool:
    """No APS counter information at all in a foreign backup (spec 9.4 rule 6)."""
    if "zigbee_rs" in (ni.stack_specific or {}):
        return False
    if ni.tc_link_key.tx_counter or any(k.tx_counter for k in ni.key_table):
        return False
    return bool(ni.children or ni.key_table or ni.nwk_addresses)


def _now_iso() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat()


__all__ = ["ControllerApplication", "ieee_text", "ieee_wire"]
