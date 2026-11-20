"""Message layer (spec 6) and the v1 command set (spec 7-9).

Layouts mirror ``zigbee-zrhp/src/msg``. Request and event classes carry their
whole payload; response classes carry the fields *after* the leading
``status`` byte (:func:`encode_response` / :func:`decode_response`).
"""

from __future__ import annotations

import dataclasses
import enum
import struct
from typing import Any

from .codec import (
    EPID,
    I8,
    IEEE,
    KEY,
    LV8,
    LV16,
    REST,
    SHA256,
    U8,
    U16,
    U32,
    U64,
    CodecError,
    ListOf,
    Struct,
    struct_type,
)
from .records import GPD_ID, RECORD, GpTranslation
from .types import Endpoint, Kind, Status

HEADER_LEN = 7
MAX_MESSAGE_PAYLOAD = 640 - HEADER_LEN
FLAG_RETRY = 0x20


class Id(enum.IntEnum):
    SYS_NEGOTIATE = 0x0001
    SYS_GET_INFO = 0x0002
    SYS_RESET = 0x0003
    SYS_GET_STATUS = 0x0004
    SYS_SET_CONFIG = 0x0005
    SYS_GET_CONFIG = 0x0006
    SYS_ECHO = 0x0007
    SYS_SET_IEEE = 0x0008
    SYS_SET_UART = 0x0009
    EVT_NCP_READY = 0x0080
    EVT_INDICATIONS_DROPPED = 0x0081
    EVT_FATAL = 0x0082
    EVT_PROTOCOL_ERROR = 0x0083
    NWK_INIT = 0x0101
    NWK_FORM = 0x0102
    NWK_LEAVE_RESET = 0x0103
    NWK_GET_INFO = 0x0104
    NWK_PERMIT_JOIN = 0x0105
    NWK_ENERGY_SCAN = 0x0106
    NWK_CHANGE_CHANNEL = 0x0107
    NWK_SET_TX_POWER = 0x0108
    NWK_CONCENTRATOR = 0x0109
    NWK_ACTIVE_SCAN = 0x010A
    NWK_ADD_ENDPOINT = 0x010B
    NWK_SET_MANUFACTURER_CODE = 0x010C
    NWK_GROUP_MEMBERSHIP = 0x010D
    NWK_REMOVE_DEVICE = 0x010E
    EVT_NETWORK_STATE = 0x0180
    EVT_DEVICE_JOINED = 0x0181
    EVT_DEVICE_AUTHORIZED = 0x0182
    EVT_DEVICE_LEFT = 0x0183
    EVT_ADDRESS_CHANGED = 0x0184
    EVT_ROUTE_RECORD = 0x0185
    EVT_NWK_STATUS = 0x0186
    EVT_PAN_ID_CONFLICT = 0x0187
    EVT_PERMIT_JOIN_STATE = 0x0188
    EVT_CHANNEL_CHANGED = 0x0189
    EVT_ENERGY_SCAN_RESULT = 0x018A
    APS_DATA_REQUEST = 0x0201
    EVT_APS_DATA_INDICATION = 0x0280
    EVT_APS_DATA_CONFIRM = 0x0281
    ZDO_CONFIG = 0x0301
    SEC_GET_NETWORK_KEY = 0x0401
    SEC_SET_TC_POLICY = 0x0402
    SEC_ADD_INSTALL_CODE = 0x0403
    SEC_ADD_LINK_KEY = 0x0404
    SEC_REMOVE_LINK_KEY = 0x0405
    SEC_ROTATE_NETWORK_KEY = 0x0406
    SEC_GET_LINK_KEY = 0x0407
    SEC_GET_FRAME_COUNTERS = 0x0408
    SEC_DERIVE_EZSP_KEY = 0x0409
    SEC_LOCK_KEY_EXPORT = 0x040A
    EVT_LINK_KEY_UPDATED = 0x0480
    EVT_KEY_FAILURE = 0x0481
    EVT_NETWORK_KEY_SWITCHED = 0x0482
    EVT_FC_CHECKPOINT = 0x0483
    TBL_LOOKUP = 0x0501
    TBL_WRITEBACK = 0x0502
    TBL_PUSH = 0x0503
    TBL_INVALIDATE = 0x0504
    TBL_SYNC = 0x0505
    TBL_READ = 0x0506
    TBL_STATS = 0x0507
    EVT_TBL_EPOCH_CHANGED = 0x0580
    EVT_TBL_PAGING = 0x0581
    BKP_EXPORT_BEGIN = 0x0601
    BKP_EXPORT_READ = 0x0602
    BKP_EXPORT_END = 0x0603
    BKP_RESTORE_BEGIN = 0x0611
    BKP_RESTORE_PUT = 0x0612
    BKP_RESTORE_COMMIT = 0x0613
    BKP_RESTORE_ABORT = 0x0614
    DIAG_GET_COUNTERS = 0x0701
    DIAG_RESET_COUNTERS = 0x0702
    DIAG_GET_NEIGHBORS = 0x0703
    DIAG_GET_ROUTES = 0x0704
    DIAG_GET_CHILDREN = 0x0705
    DIAG_GET_SOURCE_ROUTES = 0x0706
    FW_BEGIN = 0x0801
    FW_WRITE = 0x0802
    FW_FINISH = 0x0803
    FW_ACTIVATE = 0x0804
    FW_CONFIRM = 0x0805
    FW_ABORT = 0x0806
    FW_GET_SLOTS = 0x0807
    LOG_CONFIG = 0x0901
    EVT_LOG_RECORD = 0x0980
    EVT_LOG_DROPPED = 0x0981
    GP_SINK_CONFIG = 0x0A01
    GP_SET_SHARED_KEY = 0x0A02
    GP_SINK_COMMISSIONING = 0x0A03
    GP_SINK_TABLE_READ = 0x0A04
    GP_SINK_TABLE_PUT = 0x0A05
    GP_SINK_REMOVE = 0x0A06
    GP_PROXY_TABLE_READ = 0x0A07
    GP_PAIRING_CONFIGURATION = 0x0A08
    GP_SEND_PAIRING = 0x0A09
    GP_TRANSLATION_UPDATE = 0x0A0A
    GP_TRANSLATION_REQUEST = 0x0A0B
    GP_REMOTE_SINK_TABLE_REQUEST = 0x0A0C
    GP_REMOTE_PROXY_TABLE_REQUEST = 0x0A0D
    EVT_GP_FRAME = 0x0A80
    EVT_GP_COMMISSIONING = 0x0A81
    EVT_GP_COMMISSIONED = 0x0A82
    EVT_GP_COMMISSIONING_FAILED = 0x0A83
    EVT_GP_DECOMMISSIONED = 0x0A84
    EVT_GP_REMOTE_STATUS = 0x0A85
    EVT_GP_REMOTE_SINK_TABLE = 0x0A86
    EVT_GP_REMOTE_PROXY_TABLE = 0x0A87
    EVT_GP_REMOTE_TRANSLATION_TABLE = 0x0A88


_GROUP_ENDPOINT = {
    0x00: Endpoint.SYSTEM,
    0x01: Endpoint.ZIGBEE,
    0x02: Endpoint.ZIGBEE,
    0x03: Endpoint.ZIGBEE,
    0x04: Endpoint.ZIGBEE,
    0x05: Endpoint.TABLES,
    0x06: Endpoint.BULK,
    0x07: Endpoint.SYSTEM,
    0x08: Endpoint.BULK,
    0x09: Endpoint.LOG,
    0x0A: Endpoint.ZIGBEE,
}


def home_endpoint(msg_id: int) -> Endpoint | None:
    """The link endpoint a message ID belongs to (spec 6.7)."""
    return _GROUP_ENDPOINT.get(msg_id >> 8)


# --- Message header and batches ---------------------------------------------


@dataclasses.dataclass
class Message:
    kind: Kind
    msg_id: int
    tid: int
    payload: bytes = b""
    retry: bool = False

    def serialize(self) -> bytes:
        flags = (int(self.kind) << 6) | (FLAG_RETRY if self.retry else 0)
        return struct.pack("<BHHH", flags, self.msg_id, self.tid, len(self.payload)) + (
            self.payload
        )

    @property
    def status(self) -> Status | int | None:
        return Status.from_int(self.payload[0]) if self.payload else None


class BatchError(ValueError):
    """The message lengths do not tile the payload (spec 6.1)."""


def parse_batch(payload: bytes) -> list[Message]:
    """Parse a DATA payload atomically; raise :class:`BatchError` if malformed."""
    if not payload:
        raise BatchError("empty")
    out = []
    pos = 0
    n = len(payload)
    while pos < n:
        if pos + HEADER_LEN > n:
            raise BatchError("truncated header")
        flags, msg_id, tid, length = struct.unpack_from("<BHHH", payload, pos)
        kind = flags >> 6
        if kind == 3:
            raise BatchError("reserved kind")
        if flags & 0x1F:
            raise BatchError("reserved flags")
        end = pos + HEADER_LEN + length
        if end > n:
            raise BatchError("truncated message")
        out.append(
            Message(
                Kind(kind),
                msg_id,
                tid,
                bytes(payload[pos + HEADER_LEN : end]),
                bool(flags & FLAG_RETRY),
            )
        )
        pos = end
    return out


# --- Definitions ------------------------------------------------------------

REQUESTS: dict[int, type[Struct]] = {}
RESPONSES: dict[int, type[Struct]] = {}
EVENTS: dict[int, type[Struct]] = {}


class Body(Struct):
    MSG_ID: int = 0
    KIND: Kind = Kind.REQUEST

    @classmethod
    def endpoint(cls) -> Endpoint:
        ep = home_endpoint(cls.MSG_ID)
        assert ep is not None
        return ep


def _define(kind: Kind, msg_id: Id, name: str, /, **fields: Any) -> type[Body]:
    cls = struct_type(name, Body, **fields)
    cls.MSG_ID = int(msg_id)
    cls.KIND = kind
    {Kind.REQUEST: REQUESTS, Kind.RESPONSE: RESPONSES, Kind.EVENT: EVENTS}[kind][int(msg_id)] = cls
    return cls  # type: ignore[return-value]


def req(msg_id: Id, name: str, /, **fields: Any) -> type[Body]:
    return _define(Kind.REQUEST, msg_id, name, **fields)


def rsp(msg_id: Id, name: str, /, **fields: Any) -> type[Body]:
    return _define(Kind.RESPONSE, msg_id, name, **fields)


def evt(msg_id: Id, name: str, /, **fields: Any) -> type[Body]:
    return _define(Kind.EVENT, msg_id, name, **fields)


# SYSTEM (7.1)
Capacity = struct_type("Capacity", id=U8, value=U32)
ConfigValue = struct_type("ConfigValue", id=U16, value=LV8)
ConfigStatus = struct_type("ConfigStatus", id=U16, status=U8)
ConfigReadItem = struct_type("ConfigReadItem", id=U16, status=U8, value=LV8)

SysNegotiateReq = req(
    Id.SYS_NEGOTIATE, "SysNegotiateReq", major_min=U8, major_max=U8, host_caps=U64, name=LV8
)
SysNegotiateRsp = rsp(
    Id.SYS_NEGOTIATE,
    "SysNegotiateRsp",
    major=U8,
    minor=U8,
    ncp_caps=U64,
    capacities=ListOf(Capacity),
    fw=LV8,
    build_id=EPID,
    chip=U8,
)
SysGetInfoReq = req(Id.SYS_GET_INFO, "SysGetInfoReq")
SysGetInfoRsp = rsp(
    Id.SYS_GET_INFO,
    "SysGetInfoRsp",
    ieee_factory=IEEE,
    ieee_active=IEEE,
    ieee_source=U8,
    chip_rev=U16,
    flash_size=U32,
    transport=U8,
    uart_baud=U32,
    uart_flow=U8,
    board=LV8,
    product=LV8,
)
SysResetReq = req(Id.SYS_RESET, "SysResetReq", mode=U8, confirm=U32)
SysGetStatusReq = req(Id.SYS_GET_STATUS, "SysGetStatusReq")
SysGetStatusRsp = rsp(
    Id.SYS_GET_STATUS,
    "SysGetStatusRsp",
    network_state=U8,
    uptime_s=U32,
    free_aps_slots=U16,
    host_absent_queue=U16,
    dirty_writebacks=U16,
    restore_in_progress=U8,
    flags=U8,
)
SysSetConfigReq = req(Id.SYS_SET_CONFIG, "SysSetConfigReq", values=ListOf(ConfigValue))
SysSetConfigRsp = rsp(Id.SYS_SET_CONFIG, "SysSetConfigRsp", results=ListOf(ConfigStatus))
SysGetConfigReq = req(Id.SYS_GET_CONFIG, "SysGetConfigReq", ids=ListOf(U16))
SysGetConfigRsp = rsp(Id.SYS_GET_CONFIG, "SysGetConfigRsp", items=ListOf(ConfigReadItem))
SysEchoReq = req(Id.SYS_ECHO, "SysEchoReq", data=REST)
SysEchoRsp = rsp(Id.SYS_ECHO, "SysEchoRsp", data=REST)
SysSetIeeeReq = req(Id.SYS_SET_IEEE, "SysSetIeeeReq", ieee=IEEE)
SysSetUartReq = req(Id.SYS_SET_UART, "SysSetUartReq", baud=U32, flow=U8, apply_delay_ms=U16)
EvtNcpReady = evt(
    Id.EVT_NCP_READY,
    "EvtNcpReady",
    ncp_cookie=U32,
    reset_reason=U8,
    network_state=U8,
    table_epoch=U32,
    nwk_fc_limit=U32,
    aps_fc_limit=U32,
    dirty_writebacks=U16,
    dropped_indications=U32,
)
EvtIndicationsDropped = evt(
    Id.EVT_INDICATIONS_DROPPED,
    "EvtIndicationsDropped",
    endpoint=U8,
    reason=U8,
    count=U32,
    first_ms=U32,
    last_ms=U32,
)
EvtFatal = evt(Id.EVT_FATAL, "EvtFatal", kind=U8, code=U32, text=LV8)
EvtProtocolError = evt(
    Id.EVT_PROTOCOL_ERROR, "EvtProtocolError", endpoint=U8, msg_id=U16, reason=U8
)

# NETWORK (7.2)
ScanResult = struct_type(
    "ScanResult",
    channel=U8,
    pan=U16,
    epid=EPID,
    src=U16,
    lqi=U8,
    rssi=I8,
    permit=U8,
    stack_profile=U8,
    update_id=U8,
)
EnergyResult = struct_type("EnergyResult", channel=U8, max_rssi_dbm=I8, energy=U8)

NwkInitReq = req(Id.NWK_INIT, "NwkInitReq", nwk_fc_floor=U32, aps_fc_floor=U32)
NwkInitRsp = rsp(Id.NWK_INIT, "NwkInitRsp", network_state=U8)
NwkFormReq = req(
    Id.NWK_FORM,
    "NwkFormReq",
    channel_mask=U32,
    pan_id=U16,
    ext_pan_id=EPID,
    network_key=KEY,
    key_seq=U8,
    nwk_update_id=U8,
    tx_power=I8,
    nwk_manager=U16,
)
NwkLeaveResetReq = req(Id.NWK_LEAVE_RESET, "NwkLeaveResetReq", flags=U8)
NwkGetInfoReq = req(Id.NWK_GET_INFO, "NwkGetInfoReq")
NwkGetInfoRsp = rsp(
    Id.NWK_GET_INFO,
    "NwkGetInfoRsp",
    state=U8,
    pan_id=U16,
    ext_pan_id=EPID,
    channel=U8,
    channel_mask=U32,
    short=U16,
    ieee=IEEE,
    nwk_update_id=U8,
    nwk_manager=U16,
    key_seq=U8,
    security_level=U8,
    tx_power=I8,
    stack_profile=U8,
)
NwkPermitJoinReq = req(Id.NWK_PERMIT_JOIN, "NwkPermitJoinReq", duration_s=U8, target=U16, flags=U8)
NwkEnergyScanReq = req(
    Id.NWK_ENERGY_SCAN, "NwkEnergyScanReq", channel_mask=U32, duration_exp=U8, count=U8
)
NwkChangeChannelReq = req(
    Id.NWK_CHANGE_CHANNEL, "NwkChangeChannelReq", channel=U8, nwk_update_id=U8
)
NwkSetTxPowerReq = req(Id.NWK_SET_TX_POWER, "NwkSetTxPowerReq", dbm=I8)
NwkSetTxPowerRsp = rsp(Id.NWK_SET_TX_POWER, "NwkSetTxPowerRsp", applied_dbm=I8)
NwkConcentratorReq = req(
    Id.NWK_CONCENTRATOR, "NwkConcentratorReq", mode=U8, min_s=U16, max_s=U16, radius=U8
)
NwkActiveScanReq = req(Id.NWK_ACTIVE_SCAN, "NwkActiveScanReq", channel_mask=U32, duration_exp=U8)
NwkActiveScanRsp = rsp(Id.NWK_ACTIVE_SCAN, "NwkActiveScanRsp", results=ListOf(ScanResult))
NwkAddEndpointReq = req(
    Id.NWK_ADD_ENDPOINT,
    "NwkAddEndpointReq",
    ep=U8,
    profile=U16,
    device_id=U16,
    version=U8,
    in_clusters=ListOf(U16),
    out_clusters=ListOf(U16),
)
NwkSetManufacturerCodeReq = req(Id.NWK_SET_MANUFACTURER_CODE, "NwkSetManufacturerCodeReq", code=U16)
NwkGroupMembershipReq = req(
    Id.NWK_GROUP_MEMBERSHIP, "NwkGroupMembershipReq", op=U8, group=U16, ep=U8
)
NwkRemoveDeviceReq = req(Id.NWK_REMOVE_DEVICE, "NwkRemoveDeviceReq", nwk=U16, ieee=IEEE, flags=U8)
EvtNetworkState = evt(
    Id.EVT_NETWORK_STATE, "EvtNetworkState", state=U8, reason=U8, zb_status=U8, req_tid=U16
)
EvtDeviceJoined = evt(
    Id.EVT_DEVICE_JOINED,
    "EvtDeviceJoined",
    nwk=U16,
    ieee=IEEE,
    parent_nwk=U16,
    join_type=U8,
    capability=U8,
    decision=U8,
)
EvtDeviceAuthorized = evt(
    Id.EVT_DEVICE_AUTHORIZED,
    "EvtDeviceAuthorized",
    nwk=U16,
    ieee=IEEE,
    result=U8,
    link_key_type=U8,
)
EvtDeviceLeft = evt(Id.EVT_DEVICE_LEFT, "EvtDeviceLeft", nwk=U16, ieee=IEEE, flags=U8, reason=U8)
EvtAddressChanged = evt(
    Id.EVT_ADDRESS_CHANGED, "EvtAddressChanged", ieee=IEEE, old_nwk=U16, new_nwk=U16, cause=U8
)
EvtRouteRecord = evt(
    Id.EVT_ROUTE_RECORD, "EvtRouteRecord", src_nwk=U16, src_ieee=IEEE, relays=ListOf(U16)
)
EvtNwkStatus = evt(Id.EVT_NWK_STATUS, "EvtNwkStatus", dst=U16, nwk_status=U8, reporter=U16)
EvtPanIdConflict = evt(Id.EVT_PAN_ID_CONFLICT, "EvtPanIdConflict", conflicting_pan=U16, count=U8)
EvtPermitJoinState = evt(Id.EVT_PERMIT_JOIN_STATE, "EvtPermitJoinState", remaining_s=U8)
EvtChannelChanged = evt(
    Id.EVT_CHANNEL_CHANGED, "EvtChannelChanged", channel=U8, nwk_update_id=U8, req_tid=U16
)
EvtEnergyScanResult = evt(
    Id.EVT_ENERGY_SCAN_RESULT,
    "EvtEnergyScanResult",
    req_tid=U16,
    status=U8,
    results=ListOf(EnergyResult),
)


# DATA (7.3)
class AddrMode(enum.IntEnum):
    GROUP = 0x01
    NWK = 0x02
    IEEE = 0x03
    BROADCAST = 0x0F


class ApsDataRequest(Body):
    """``APS_DATA_REQUEST``; tx_options bits 4 and 6 follow ``alias``/``relays``."""

    MSG_ID = int(Id.APS_DATA_REQUEST)
    KIND = Kind.REQUEST
    _fields = (
        ("dst_mode", U8),
        ("dst", None),
        ("dst_ep", U8),
        ("src_ep", U8),
        ("profile", U16),
        ("cluster", U16),
        ("tx_options", U8),
        ("radius", U8),
        ("non_member_radius", U8),
        ("priority", U8),
        ("relays", None),
        ("alias", None),
        ("asdu", LV16),
    )

    def __init__(self, **kwargs: Any) -> None:
        defaults: dict[str, Any] = {
            "dst_mode": AddrMode.NWK,
            "dst": 0,
            "dst_ep": 0,
            "src_ep": 0,
            "profile": 0,
            "cluster": 0,
            "tx_options": 0,
            "radius": 0,
            "non_member_radius": 0,
            "priority": 1,
            "relays": None,
            "alias": None,
            "asdu": b"",
        }
        unknown = set(kwargs) - set(defaults)
        if unknown:
            raise TypeError(f"ApsDataRequest: unknown fields {sorted(unknown)}")
        for k, v in {**defaults, **kwargs}.items():
            setattr(self, k, v)

    def serialize(self) -> bytes:
        opts = self.tx_options & ~(0x40 | 0x10)
        if self.relays is not None:
            opts |= 0x40
        if self.alias is not None:
            opts |= 0x10
        out = U8.pack(self.dst_mode)
        if self.dst_mode == AddrMode.IEEE:
            out += IEEE.pack(self.dst)
        elif self.dst_mode in (AddrMode.GROUP, AddrMode.NWK, AddrMode.BROADCAST):
            out += U16.pack(self.dst)
        else:
            raise CodecError(f"invalid dst_mode {self.dst_mode}")
        out += struct.pack(
            "<BBHHBBBB",
            self.dst_ep,
            self.src_ep,
            self.profile,
            self.cluster,
            opts,
            self.radius,
            self.non_member_radius,
            self.priority,
        )
        if self.relays is not None:
            out += ListOf(U16).pack(self.relays)
        if self.alias is not None:
            out += struct.pack("<HB", *self.alias)
        return out + LV16.pack(self.asdu)

    @classmethod
    def unpack(cls, data: bytes, off: int) -> tuple[ApsDataRequest, int]:
        mode, off = U8.unpack(data, off)
        if mode == AddrMode.IEEE:
            dst, off = IEEE.unpack(data, off)
        elif mode in (AddrMode.GROUP, AddrMode.NWK, AddrMode.BROADCAST):
            dst, off = U16.unpack(data, off)
        else:
            raise CodecError(f"invalid dst_mode {mode}")
        if off + 10 > len(data):
            raise CodecError("truncated")
        dst_ep, src_ep, profile, cluster, opts, radius, nmr, prio = struct.unpack_from(
            "<BBHHBBBB", data, off
        )
        off += 10
        relays = alias = None
        if opts & 0x40:
            relays, off = ListOf(U16).unpack(data, off)
        if opts & 0x10:
            if off + 3 > len(data):
                raise CodecError("truncated")
            alias = struct.unpack_from("<HB", data, off)
            off += 3
        asdu, off = LV16.unpack(data, off)
        return (
            cls(
                dst_mode=mode,
                dst=dst,
                dst_ep=dst_ep,
                src_ep=src_ep,
                profile=profile,
                cluster=cluster,
                tx_options=opts,
                radius=radius,
                non_member_radius=nmr,
                priority=prio,
                relays=relays,
                alias=tuple(alias) if alias else None,
                asdu=asdu,
            ),
            off,
        )


REQUESTS[ApsDataRequest.MSG_ID] = ApsDataRequest

EvtApsDataIndication = evt(
    Id.EVT_APS_DATA_INDICATION,
    "EvtApsDataIndication",
    dst_mode=U8,
    dst=U16,
    dst_ep=U8,
    src_nwk=U16,
    src_ieee=IEEE,
    src_ep=U8,
    profile=U16,
    cluster=U16,
    flags=U8,
    lqi=U8,
    rssi=I8,
    last_hop_nwk=U16,
    aps_counter=U8,
    key_source=U8,
    rx_time_ms=U32,
    asdu=LV16,
)
EvtApsDataConfirm = evt(
    Id.EVT_APS_DATA_CONFIRM,
    "EvtApsDataConfirm",
    req_tid=U16,
    status=U8,
    zb_status=U8,
    aps_counter=U8,
    dst_nwk=U16,
    flags=U8,
    elapsed_ms=U16,
)
ZdoConfigReq = req(Id.ZDO_CONFIG, "ZdoConfigReq", flags=U8)

# SECURITY (7.5)
SecGetNetworkKeyReq = req(Id.SEC_GET_NETWORK_KEY, "SecGetNetworkKeyReq", which=U8)
SecGetNetworkKeyRsp = rsp(
    Id.SEC_GET_NETWORK_KEY, "SecGetNetworkKeyRsp", key=KEY, seq=U8, nwk_fc_limit=U32
)
SecSetTcPolicyReq = req(
    Id.SEC_SET_TC_POLICY,
    "SecSetTcPolicyReq",
    allow_join=U8,
    require_tclk_update=U8,
    allow_tc_rejoin=U8,
    allow_app_link_keys=U8,
    join_timeout_s=U16,
)
SecAddInstallCodeReq = req(Id.SEC_ADD_INSTALL_CODE, "SecAddInstallCodeReq", ieee=IEEE, code=LV8)
SecAddInstallCodeRsp = rsp(Id.SEC_ADD_INSTALL_CODE, "SecAddInstallCodeRsp", derived_key=KEY)
SecAddLinkKeyReq = req(
    Id.SEC_ADD_LINK_KEY,
    "SecAddLinkKeyReq",
    ieee=IEEE,
    key=KEY,
    key_type=U8,
    attrs=U8,
    rx_floor=U32,
    flags=U8,
)
SecRemoveLinkKeyReq = req(Id.SEC_REMOVE_LINK_KEY, "SecRemoveLinkKeyReq", ieee=IEEE)
SecRotateNetworkKeyReq = req(
    Id.SEC_ROTATE_NETWORK_KEY, "SecRotateNetworkKeyReq", key=KEY, mode=U8, switch_delay_s=U16
)
SecGetLinkKeyReq = req(Id.SEC_GET_LINK_KEY, "SecGetLinkKeyReq", ieee=IEEE)
SecGetLinkKeyRsp = rsp(
    Id.SEC_GET_LINK_KEY,
    "SecGetLinkKeyRsp",
    key=KEY,
    key_type=U8,
    attrs=U8,
    tx=U32,
    rx_floor=U32,
)
SecGetFrameCountersReq = req(Id.SEC_GET_FRAME_COUNTERS, "SecGetFrameCountersReq")
SecGetFrameCountersRsp = rsp(
    Id.SEC_GET_FRAME_COUNTERS,
    "SecGetFrameCountersRsp",
    nwk_current=U32,
    nwk_limit=U32,
    aps_current=U32,
    aps_limit=U32,
    stride=U32,
)
SecDeriveEzspKeyReq = req(Id.SEC_DERIVE_EZSP_KEY, "SecDeriveEzspKeyReq", ieee=IEEE)
SecDeriveEzspKeyRsp = rsp(Id.SEC_DERIVE_EZSP_KEY, "SecDeriveEzspKeyRsp", key=KEY)
SecLockKeyExportReq = req(Id.SEC_LOCK_KEY_EXPORT, "SecLockKeyExportReq", confirm=U32)
EvtLinkKeyUpdated = evt(
    Id.EVT_LINK_KEY_UPDATED,
    "EvtLinkKeyUpdated",
    ieee=IEEE,
    nwk=U16,
    key_type=U8,
    attrs=U8,
    origin=U8,
)
EvtKeyFailure = evt(Id.EVT_KEY_FAILURE, "EvtKeyFailure", ieee=IEEE, nwk=U16, reason=U8)
EvtNetworkKeySwitched = evt(
    Id.EVT_NETWORK_KEY_SWITCHED, "EvtNetworkKeySwitched", new_seq=U8, req_tid=U16
)
EvtFcCheckpoint = evt(
    Id.EVT_FC_CHECKPOINT,
    "EvtFcCheckpoint",
    domain=U8,
    key_seq=U8,
    durable_limit=U32,
    generation=U32,
)


# TABLES (8.5)
class TableKey(Struct):
    """``u8 key_type (1 IEEE, 2 NWK), key[8|2]``."""

    _fields = (("key_type", U8), ("key", None))

    def __init__(self, key_type: int = 2, key: Any = 0) -> None:
        self.key_type = key_type
        self.key = key

    def serialize(self) -> bytes:
        if self.key_type == 1:
            return b"\x01" + IEEE.pack(self.key)
        if self.key_type == 2:
            return b"\x02" + U16.pack(self.key)
        raise CodecError("invalid table key type")

    @classmethod
    def unpack(cls, data: bytes, off: int) -> tuple[TableKey, int]:
        kt, off = U8.unpack(data, off)
        if kt == 1:
            key, off = IEEE.unpack(data, off)
        elif kt == 2:
            key, off = U16.unpack(data, off)
        else:
            raise CodecError("invalid table key type")
        return cls(kt, key), off


PushResult = struct_type("PushResult", status=U8, rev=U32)
TblReadEntry = struct_type("TblReadEntry", rev=U32, state=U8, record=RECORD)

TblLookupReq = req(Id.TBL_LOOKUP, "TblLookupReq", table=U8, key=TableKey)
TblLookupRsp = rsp(Id.TBL_LOOKUP, "TblLookupRsp", rev=U32, record=RECORD)
TblWritebackReq = req(
    Id.TBL_WRITEBACK, "TblWritebackReq", table=U8, reason=U8, rev=U32, record=RECORD
)
TblPushReq = req(Id.TBL_PUSH, "TblPushReq", table=U8, flags=U8, records=ListOf(RECORD))
TblPushRsp = rsp(Id.TBL_PUSH, "TblPushRsp", results=ListOf(PushResult))
TblInvalidateReq = req(Id.TBL_INVALIDATE, "TblInvalidateReq", table=U8, key=TableKey)
TblSyncReq = req(
    Id.TBL_SYNC,
    "TblSyncReq",
    host_db_epoch=U32,
    last_ncp_table_epoch=U32,
    host_max_rev=U32,
    flags=U8,
)
TblSyncRsp = rsp(
    Id.TBL_SYNC,
    "TblSyncRsp",
    ncp_table_epoch=U32,
    host_acked_rev=U32,
    dirty=U16,
    cached_devices=U16,
    cached_routes=U16,
    paging_active=U8,
)
TblReadReq = req(Id.TBL_READ, "TblReadReq", table=U8, cursor=U16, max=U8)
TblReadRsp = rsp(Id.TBL_READ, "TblReadRsp", next_cursor=U16, entries=ListOf(TblReadEntry))
TblStatsReq = req(Id.TBL_STATS, "TblStatsReq", table=U8)
TblStatsRsp = rsp(
    Id.TBL_STATS,
    "TblStatsRsp",
    capacity=U16,
    used=U16,
    dirty=U16,
    pinned=U16,
    hits=U32,
    misses=U32,
    evictions=U32,
    lookup_timeouts=U32,
)
EvtTblEpochChanged = evt(Id.EVT_TBL_EPOCH_CHANGED, "EvtTblEpochChanged", new_epoch=U32, reason=U8)
EvtTblPaging = evt(Id.EVT_TBL_PAGING, "EvtTblPaging", active=U8, cached=U16, capacity=U16)

# BACKUP (9.4, 9.5)
RestoreNoteEntry = struct_type("RestoreNoteEntry", index=U16, note=U8)
BkpExportBeginReq = req(Id.BKP_EXPORT_BEGIN, "BkpExportBeginReq", flags=U8)
BkpExportBeginRsp = rsp(Id.BKP_EXPORT_BEGIN, "BkpExportBeginRsp", txn=U16, record_count=U32)
BkpExportReadReq = req(Id.BKP_EXPORT_READ, "BkpExportReadReq", txn=U16, max_bytes=U16)
BkpExportReadRsp = rsp(Id.BKP_EXPORT_READ, "BkpExportReadRsp", more=U8, records=REST)
BkpExportEndReq = req(Id.BKP_EXPORT_END, "BkpExportEndReq", txn=U16)
BkpRestoreBeginReq = req(
    Id.BKP_RESTORE_BEGIN,
    "BkpRestoreBeginReq",
    flags=U8,
    nwk_margin=U32,
    aps_margin=U32,
    expected_records=U32,
)
BkpRestoreBeginRsp = rsp(
    Id.BKP_RESTORE_BEGIN, "BkpRestoreBeginRsp", txn=U16, max_records_per_put=U16
)
BkpRestorePutReq = req(Id.BKP_RESTORE_PUT, "BkpRestorePutReq", txn=U16, records=REST)
BkpRestorePutRsp = rsp(
    Id.BKP_RESTORE_PUT, "BkpRestorePutRsp", accepted=U16, notes=ListOf(RestoreNoteEntry)
)
BkpRestoreCommitReq = req(Id.BKP_RESTORE_COMMIT, "BkpRestoreCommitReq", txn=U16)
BkpRestoreCommitRsp = rsp(
    Id.BKP_RESTORE_COMMIT,
    "BkpRestoreCommitRsp",
    nwk_fc_start=U32,
    aps_fc_start=U32,
    link_keys_on_ncp=U16,
    link_keys_host_backed=U16,
    children=U16,
)
BkpRestoreAbortReq = req(Id.BKP_RESTORE_ABORT, "BkpRestoreAbortReq", txn=U16)

# DIAG (7.8)
Counter = struct_type("Counter", id=U16, value=U32)
Neighbor = struct_type(
    "Neighbor",
    ieee=IEEE,
    nwk=U16,
    device_type=U8,
    rx_on=U8,
    relationship=U8,
    lqi=U8,
    outgoing_cost=U8,
    age=U8,
)
Route = struct_type("Route", dst=U16, next_hop=U16, status=U8, flags=U8)
Child = struct_type("Child", ieee=IEEE, nwk=U16, capability=U8, timeout_exp=U8, last_poll_ms=U32)
SourceRoute = struct_type("SourceRoute", dst=U16, relays=ListOf(U16))
DiagGetCountersReq = req(Id.DIAG_GET_COUNTERS, "DiagGetCountersReq", group_mask=U8)
DiagGetCountersRsp = rsp(Id.DIAG_GET_COUNTERS, "DiagGetCountersRsp", counters=ListOf(Counter))
DiagResetCountersReq = req(Id.DIAG_RESET_COUNTERS, "DiagResetCountersReq", group_mask=U8)
DiagGetNeighborsReq = req(Id.DIAG_GET_NEIGHBORS, "DiagGetNeighborsReq", start=U8)
DiagGetNeighborsRsp = rsp(
    Id.DIAG_GET_NEIGHBORS, "DiagGetNeighborsRsp", total=U8, entries=ListOf(Neighbor)
)
DiagGetRoutesReq = req(Id.DIAG_GET_ROUTES, "DiagGetRoutesReq", start=U8)
DiagGetRoutesRsp = rsp(Id.DIAG_GET_ROUTES, "DiagGetRoutesRsp", total=U8, entries=ListOf(Route))
DiagGetChildrenReq = req(Id.DIAG_GET_CHILDREN, "DiagGetChildrenReq", start=U8)
DiagGetChildrenRsp = rsp(
    Id.DIAG_GET_CHILDREN, "DiagGetChildrenRsp", total=U8, entries=ListOf(Child)
)
DiagGetSourceRoutesReq = req(Id.DIAG_GET_SOURCE_ROUTES, "DiagGetSourceRoutesReq", start=U8)
DiagGetSourceRoutesRsp = rsp(
    Id.DIAG_GET_SOURCE_ROUTES, "DiagGetSourceRoutesRsp", total=U8, entries=ListOf(SourceRoute)
)

# FIRMWARE (7.9)
FwSlot = struct_type("FwSlot", slot=U8, state=U8, version=U32, sha256=SHA256)
FwBeginReq = req(
    Id.FW_BEGIN, "FwBeginReq", image_size=U32, format=U8, sha256=SHA256, version=U32, flags=U8
)
FwBeginRsp = rsp(Id.FW_BEGIN, "FwBeginRsp", max_chunk=U16, slot=U8)
FwWriteReq = req(Id.FW_WRITE, "FwWriteReq", offset=U32, data=REST)
FwWriteRsp = rsp(Id.FW_WRITE, "FwWriteRsp", next_offset=U32)
FwFinishReq = req(Id.FW_FINISH, "FwFinishReq")
FwFinishRsp = rsp(Id.FW_FINISH, "FwFinishRsp", verify_result=U8)
FwActivateReq = req(Id.FW_ACTIVATE, "FwActivateReq", delay_ms=U16)
FwConfirmReq = req(Id.FW_CONFIRM, "FwConfirmReq")
FwAbortReq = req(Id.FW_ABORT, "FwAbortReq")
FwGetSlotsReq = req(Id.FW_GET_SLOTS, "FwGetSlotsReq")
FwGetSlotsRsp = rsp(Id.FW_GET_SLOTS, "FwGetSlotsRsp", slots=ListOf(FwSlot))

# LOG (7.10)
LogConfigReq = req(Id.LOG_CONFIG, "LogConfigReq", level=U8, module_mask=U32)
EvtLogRecord = evt(
    Id.EVT_LOG_RECORD, "EvtLogRecord", time_ms=U32, level=U8, module=U8, seq=U16, text=REST
)
EvtLogDropped = evt(Id.EVT_LOG_DROPPED, "EvtLogDropped", count=U32, first_seq=U16)

# GREEN POWER (7.11)
GpGroup = struct_type("GpGroup", group=U16, alias=U16)
GpSinkConfigReq = req(
    Id.GP_SINK_CONFIG,
    "GpSinkConfigReq",
    mode=U8,
    communication_mode=U8,
    group=U16,
    exit_mode=U8,
    window_s=U16,
    security_level=U8,
    groupcast_radius=U8,
)
GpSetSharedKeyReq = req(Id.GP_SET_SHARED_KEY, "GpSetSharedKeyReq", key_type=U8, key=KEY)
GpSinkCommissioningReq = req(
    Id.GP_SINK_COMMISSIONING, "GpSinkCommissioningReq", action=U8, flags=U8, window_s=U16
)
GpSinkTableReadReq = req(Id.GP_SINK_TABLE_READ, "GpSinkTableReadReq", start=U8)
GpSinkTableReadRsp = rsp(
    Id.GP_SINK_TABLE_READ, "GpSinkTableReadRsp", total=U8, records=ListOf(RECORD)
)
GpSinkTablePutReq = req(Id.GP_SINK_TABLE_PUT, "GpSinkTablePutReq", flags=U8, records=ListOf(RECORD))
GpSinkTablePutRsp = rsp(Id.GP_SINK_TABLE_PUT, "GpSinkTablePutRsp", statuses=ListOf(U8))
GpSinkRemoveReq = req(Id.GP_SINK_REMOVE, "GpSinkRemoveReq", gpd_id=GPD_ID, flags=U8)
GpProxyTableReadReq = req(Id.GP_PROXY_TABLE_READ, "GpProxyTableReadReq", start=U8)
GpProxyTableReadRsp = rsp(
    Id.GP_PROXY_TABLE_READ, "GpProxyTableReadRsp", total=U8, records=ListOf(RECORD)
)
GpPairingConfigurationReq = req(
    Id.GP_PAIRING_CONFIGURATION,
    "GpPairingConfigurationReq",
    dst=U16,
    actions=U8,
    gpd_id=GPD_ID,
    device_id=U8,
    communication_mode=U8,
    flags=U8,
    assigned_alias=U16,
    groupcast_radius=U8,
    security_level=U8,
    key_type=U8,
    key=KEY,
    frame_counter=U32,
    groups=ListOf(GpGroup),
    paired=U8,
    endpoints=ListOf(U8),
    app_info=U8,
    manufacturer_id=U16,
    model_id=U16,
    gpd_commands=ListOf(U8),
    server_clusters=ListOf(U16),
    client_clusters=ListOf(U16),
)
GpSendPairingReq = req(
    Id.GP_SEND_PAIRING,
    "GpSendPairingReq",
    dst=U16,
    flags=U8,
    gpd_id=GPD_ID,
    communication_mode=U8,
    security_level=U8,
    key_type=U8,
    sink_ieee=IEEE,
    sink_nwk=U16,
    sink_group=U16,
    device_id=U8,
    frame_counter=U32,
    key=KEY,
    assigned_alias=U16,
    groupcast_radius=U8,
)
GpTranslationUpdateReq = req(
    Id.GP_TRANSLATION_UPDATE,
    "GpTranslationUpdateReq",
    dst=U16,
    action=U8,
    gpd_id=GPD_ID,
    translations=ListOf(GpTranslation),
)
GpTranslationRequestReq = req(
    Id.GP_TRANSLATION_REQUEST, "GpTranslationRequestReq", dst=U16, start_index=U8
)
GpRemoteSinkTableRequestReq = req(
    Id.GP_REMOTE_SINK_TABLE_REQUEST,
    "GpRemoteSinkTableRequestReq",
    dst=U16,
    index=U8,
    gpd_id=GPD_ID,
)
GpRemoteProxyTableRequestReq = req(
    Id.GP_REMOTE_PROXY_TABLE_REQUEST,
    "GpRemoteProxyTableRequestReq",
    dst=U16,
    index=U8,
    gpd_id=GPD_ID,
)
GpRemoteRsp = struct_type("GpRemoteRsp", Body, zcl_tsn=U8)
for _id in (
    Id.GP_PAIRING_CONFIGURATION,
    Id.GP_SEND_PAIRING,
    Id.GP_TRANSLATION_UPDATE,
    Id.GP_TRANSLATION_REQUEST,
    Id.GP_REMOTE_SINK_TABLE_REQUEST,
    Id.GP_REMOTE_PROXY_TABLE_REQUEST,
):
    RESPONSES[int(_id)] = GpRemoteRsp

EvtGpFrame = evt(
    Id.EVT_GP_FRAME,
    "EvtGpFrame",
    origin=U8,
    result=U8,
    gpd_id=GPD_ID,
    device_id=U8,
    command_id=U8,
    frame_counter=U32,
    security_level=U8,
    key_type=U8,
    flags=U8,
    proxy_nwk=U16,
    gpp_gpd_link=U8,
    rssi=I8,
    lqi=U8,
    payload=LV8,
)
EvtGpCommissioning = evt(
    Id.EVT_GP_COMMISSIONING,
    "EvtGpCommissioning",
    state=U8,
    window_s=U16,
    involve_proxies=U8,
    exit_reason=U8,
)
EvtGpCommissioned = evt(
    Id.EVT_GP_COMMISSIONED,
    "EvtGpCommissioned",
    gpd_id=GPD_ID,
    device_id=U8,
    flags=U8,
    record=RECORD,
)
EvtGpCommissioningFailed = evt(
    Id.EVT_GP_COMMISSIONING_FAILED, "EvtGpCommissioningFailed", gpd_id=GPD_ID, reason=U8
)
EvtGpDecommissioned = evt(Id.EVT_GP_DECOMMISSIONED, "EvtGpDecommissioned", gpd_id=GPD_ID)
EvtGpRemoteStatus = evt(
    Id.EVT_GP_REMOTE_STATUS,
    "EvtGpRemoteStatus",
    src_nwk=U16,
    zcl_tsn=U8,
    command_id=U8,
    zcl_status=U8,
)
_remote_table = {
    "src_nwk": U16,
    "zcl_tsn": U8,
    "status": U8,
    "total": U8,
    "start_index": U8,
    "flags": U8,
    "records": ListOf(RECORD),
}
EvtGpRemoteSinkTable = evt(Id.EVT_GP_REMOTE_SINK_TABLE, "EvtGpRemoteSinkTable", **_remote_table)
EvtGpRemoteProxyTable = evt(Id.EVT_GP_REMOTE_PROXY_TABLE, "EvtGpRemoteProxyTable", **_remote_table)
EvtGpRemoteTranslationTable = evt(
    Id.EVT_GP_REMOTE_TRANSLATION_TABLE, "EvtGpRemoteTranslationTable", **_remote_table
)


# --- Helpers ------------------------------------------------------------------


def encode_response(body: Struct | None, status: int = Status.SUCCESS) -> bytes:
    return bytes([int(status)]) + (body.serialize() if body is not None else b"")


def decode_response(msg_id: int, payload: bytes) -> tuple[Status | int, Struct | None]:
    """``(status, body)``; ``body`` is ``None`` when only a status was sent."""
    if not payload:
        raise CodecError("empty response")
    status = Status.from_int(payload[0])
    cls = RESPONSES.get(msg_id)
    if cls is None or len(payload) == 1:
        return status, None
    try:
        return status, cls.deserialize(payload[1:])
    except CodecError:
        if status == Status.SUCCESS:
            raise
        return status, None


def decode_message(msg: Message) -> Struct | None:
    """Typed body of a request or event (``None`` for unknown IDs)."""
    table = REQUESTS if msg.kind is Kind.REQUEST else EVENTS
    cls = table.get(msg.msg_id)
    if cls is None:
        return None
    return cls.deserialize(msg.payload)


def name_of(msg_id: int) -> str:
    try:
        return Id(msg_id).name
    except ValueError:
        return f"0x{msg_id:04X}"
