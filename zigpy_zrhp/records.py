"""Records shared by BACKUP, TABLES and GREEN POWER (spec 9.3, 7.11)."""

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
    REST,
    U8,
    U16,
    U32,
    CodecError,
    ListOf,
    Struct,
    struct_type,
)
from .crc import crc32c


class RecordType(enum.IntEnum):
    NODE = 0x01
    NETWORK = 0x02
    NETWORK_KEY = 0x03
    TC_LINK_KEY = 0x04
    DEVICE = 0x05
    EZSP_HASHED_TCLK = 0x06
    SOURCE_ROUTE = 0x08
    GP_PROXY = 0x09
    RS_PARAMS = 0x0A
    GP_SINK = 0x0B
    GP_TRANSLATION = 0x0C
    END = 0xFF


class DeviceFlags(enum.IntFlag):
    IS_CHILD = 0x01
    LINK = 0x02
    CHILD_INFO = 0x04
    NWK_VALID = 0x08


class KeyAttrs(enum.IntEnum):
    PROVISIONAL = 0
    UNVERIFIED = 1
    VERIFIED = 2


class KeyOrigin(enum.IntEnum):
    GLOBAL = 0
    INSTALL_CODE = 1
    TC_GENERATED = 2
    IMPORTED = 3
    EZSP_HASHED = 4


class RestoreNote(enum.IntEnum):
    HOST_BACKED = 1
    CHILD_DEMOTED = 2
    IGNORED = 3
    FLOOR_RAISED = 4


@dataclasses.dataclass(frozen=True)
class GpdId:
    """``u8 app_id``, then ``u32 src_id`` (app 0) or ``[8] ieee, u8 endpoint`` (app 2)."""

    app_id: int = 0
    src_id: int | None = None
    ieee: bytes | None = None
    endpoint: int | None = None

    @classmethod
    def srcid(cls, src_id: int) -> GpdId:
        return cls(0, src_id=src_id)

    @staticmethod
    def make_default() -> GpdId:
        return GpdId(0, src_id=0)

    @staticmethod
    def pack(value: GpdId) -> bytes:
        if value.app_id == 0:
            return struct.pack("<BI", 0, value.src_id or 0)
        if value.app_id == 2:
            return b"\x02" + bytes(value.ieee or bytes(8)) + bytes([value.endpoint or 0])
        raise CodecError(f"unsupported GPD application ID {value.app_id}")

    @staticmethod
    def unpack(data: bytes, off: int) -> tuple[GpdId, int]:
        app, off = U8.unpack(data, off)
        if app == 0:
            src, off = U32.unpack(data, off)
            return GpdId(0, src_id=src), off
        if app == 2:
            ieee, off = IEEE.unpack(data, off)
            ep, off = U8.unpack(data, off)
            return GpdId(2, ieee=ieee, endpoint=ep), off
        raise CodecError(f"unsupported GPD application ID {app}")


GPD_ID = GpdId

NodeRecord = struct_type("NodeRecord", ieee=IEEE, nwk=U16, logical_type=U8, flags=U8)
NetworkRecord = struct_type(
    "NetworkRecord",
    pan_id=U16,
    ext_pan_id=EPID,
    channel=U8,
    channel_mask=U32,
    nwk_update_id=U8,
    nwk_manager=U16,
    security_level=U8,
    tx_power=I8,
)
NetworkKeyRecord = struct_type("NetworkKeyRecord", key=KEY, seq=U8, tx_counter=U32, flags=U8)
TcLinkKeyRecord = struct_type("TcLinkKeyRecord", key=KEY, tc_ieee=IEEE, tx_counter=U32, flags=U8)
ChildInfo = struct_type("ChildInfo", capability=U8, timeout_exp=U8)
LinkBlock = struct_type(
    "LinkBlock",
    key=KEY,
    key_seq=U8,
    attrs=U8,
    origin=U8,
    tx_counter=U32,
    rx_floor=U32,
)
SourceRouteRecord = struct_type("SourceRouteRecord", dst=U16, relays=ListOf(U16))
GpProxyRecord = struct_type("GpProxyRecord", format_version=U8, entries=REST)
RsParamsRecord = struct_type(
    "RsParamsRecord",
    fc_stride=U32,
    table_epoch=U32,
    nwk_fc_limit=U32,
    aps_fc_limit=U32,
    flags=U8,
)
EndRecord = struct_type("EndRecord", record_count=U32, crc32c=U32)


class EzspHashedTclkRecord(Struct):
    _fields = (("seed", KEY),)


class DeviceRecord(Struct):
    """``DEVICE``: flag bits 1 (link) and 2 (child info) follow ``link``/``child``."""

    _fields = (
        ("ieee", IEEE),
        ("nwk", U16),
        ("flags", U8),
        ("child", None),
        ("link", None),
    )

    def __init__(
        self,
        ieee: bytes = bytes(8),
        nwk: int = 0xFFFF,
        flags: int = 0,
        child: Any = None,
        link: Any = None,
    ) -> None:
        self.ieee = ieee
        self.nwk = nwk
        self.flags = flags
        self.child = child
        self.link = link

    def serialize(self) -> bytes:
        flags = self.flags & ~(DeviceFlags.LINK | DeviceFlags.CHILD_INFO)
        if self.child is not None:
            flags |= DeviceFlags.CHILD_INFO
        if self.link is not None:
            flags |= DeviceFlags.LINK
        out = IEEE.pack(self.ieee) + U16.pack(self.nwk) + U8.pack(flags)
        if self.child is not None:
            out += self.child.serialize()
        if self.link is not None:
            out += self.link.serialize()
        return out

    @classmethod
    def unpack(cls, data: bytes, off: int) -> tuple[DeviceRecord, int]:
        ieee, off = IEEE.unpack(data, off)
        nwk, off = U16.unpack(data, off)
        flags, off = U8.unpack(data, off)
        child = link = None
        if flags & DeviceFlags.CHILD_INFO:
            child, off = ChildInfo.unpack(data, off)
        if flags & DeviceFlags.LINK:
            link, off = LinkBlock.unpack(data, off)
        return cls(ieee, nwk, flags, child, link), off

    @property
    def is_child(self) -> bool:
        return bool(self.flags & DeviceFlags.IS_CHILD)

    @property
    def nwk_valid(self) -> bool:
        return bool(self.flags & DeviceFlags.NWK_VALID)


class GpSinkFlags(enum.IntFlag):
    MAC_SEQ_CAPABLE = 0x01
    RX_ON_CAPABLE = 0x02
    FIXED_LOCATION = 0x04
    KEY_PRESENT = 0x08


class GpSinkRecord(Struct):
    """``GP_SINK``: flag bit 3 (key present) follows ``key``."""

    _fields = (
        ("gpd_id", GpdId),
        ("device_id", U8),
        ("communication_mode", U8),
        ("group", U16),
        ("assigned_alias", U16),
        ("flags", U8),
        ("security_level", U8),
        ("key_type", U8),
        ("key", None),
        ("frame_counter", U32),
        ("groupcast_radius", U8),
    )

    def __init__(self, **kwargs: Any) -> None:
        defaults = {
            "gpd_id": GpdId.make_default(),
            "device_id": 0,
            "communication_mode": 2,
            "group": 0xFFFF,
            "assigned_alias": 0xFFFF,
            "flags": 0,
            "security_level": 0,
            "key_type": 0,
            "key": None,
            "frame_counter": 0,
            "groupcast_radius": 0,
        }
        unknown = set(kwargs) - set(defaults)
        if unknown:
            raise TypeError(f"GpSinkRecord: unknown fields {sorted(unknown)}")
        for k, v in {**defaults, **kwargs}.items():
            setattr(self, k, v)

    def serialize(self) -> bytes:
        flags = self.flags & ~GpSinkFlags.KEY_PRESENT
        if self.key is not None:
            flags |= GpSinkFlags.KEY_PRESENT
        out = GpdId.pack(self.gpd_id) + struct.pack(
            "<BBHHBBB",
            self.device_id,
            self.communication_mode,
            self.group,
            self.assigned_alias,
            flags,
            self.security_level,
            self.key_type,
        )
        if self.key is not None:
            out += KEY.pack(self.key)
        return out + struct.pack("<IB", self.frame_counter, self.groupcast_radius)

    @classmethod
    def unpack(cls, data: bytes, off: int) -> tuple[GpSinkRecord, int]:
        gpd_id, off = GpdId.unpack(data, off)
        if off + 9 > len(data):
            raise CodecError("truncated")
        device_id, comm, group, alias, flags, level, key_type = struct.unpack_from(
            "<BBHHBBB", data, off
        )
        off += 9
        key = None
        if flags & GpSinkFlags.KEY_PRESENT:
            key, off = KEY.unpack(data, off)
        counter, off = U32.unpack(data, off)
        radius, off = U8.unpack(data, off)
        return (
            cls(
                gpd_id=gpd_id,
                device_id=device_id,
                communication_mode=comm,
                group=group,
                assigned_alias=alias,
                flags=flags,
                security_level=level,
                key_type=key_type,
                key=key,
                frame_counter=counter,
                groupcast_radius=radius,
            ),
            off,
        )


class GpTranslation(Struct):
    """One GPD command -> ZCL command translation (7.11).

    ``payload_len`` 0xFE = derived, 0xFF = GPD payload copied; neither carries
    payload bytes.
    """

    DERIVED = 0xFE
    COPY_GPD = 0xFF

    _fields = (
        ("gpd_command", U8),
        ("endpoint", U8),
        ("profile", U16),
        ("cluster", U16),
        ("zcl_command", U8),
        ("payload_len", U8),
        ("payload", REST),
    )

    def __init__(self, **kwargs: Any) -> None:
        kwargs.setdefault("profile", 0x0104)
        if "payload_len" not in kwargs:
            kwargs["payload_len"] = len(kwargs.get("payload", b""))
        super().__init__(**kwargs)

    def serialize(self) -> bytes:
        fixed = self.payload_len < self.DERIVED
        if (fixed and self.payload_len != len(self.payload)) or (not fixed and self.payload):
            raise CodecError("translation payload length mismatch")
        return (
            struct.pack(
                "<BBHHBB",
                self.gpd_command,
                self.endpoint,
                self.profile,
                self.cluster,
                self.zcl_command,
                self.payload_len,
            )
            + self.payload
        )

    @classmethod
    def unpack(cls, data: bytes, off: int) -> tuple[GpTranslation, int]:
        if off + 8 > len(data):
            raise CodecError("truncated")
        cmd, ep, profile, cluster, zcl, plen = struct.unpack_from("<BBHHBB", data, off)
        off += 8
        payload = b""
        if plen < cls.DERIVED:
            if off + plen > len(data):
                raise CodecError("truncated")
            payload = bytes(data[off : off + plen])
            off += plen
        return (
            cls(
                gpd_command=cmd,
                endpoint=ep,
                profile=profile,
                cluster=cluster,
                zcl_command=zcl,
                payload_len=plen,
                payload=payload,
            ),
            off,
        )


GpTranslationRecord = struct_type("GpTranslationRecord", gpd_id=GpdId, translation=GpTranslation)

_RECORD_CLASSES: dict[int, type[Struct]] = {
    RecordType.NODE: NodeRecord,
    RecordType.NETWORK: NetworkRecord,
    RecordType.NETWORK_KEY: NetworkKeyRecord,
    RecordType.TC_LINK_KEY: TcLinkKeyRecord,
    RecordType.DEVICE: DeviceRecord,
    RecordType.EZSP_HASHED_TCLK: EzspHashedTclkRecord,
    RecordType.SOURCE_ROUTE: SourceRouteRecord,
    RecordType.GP_PROXY: GpProxyRecord,
    RecordType.RS_PARAMS: RsParamsRecord,
    RecordType.GP_SINK: GpSinkRecord,
    RecordType.GP_TRANSLATION: GpTranslationRecord,
    RecordType.END: EndRecord,
}
_TYPE_OF = {cls: rtype for rtype, cls in _RECORD_CLASSES.items()}


@dataclasses.dataclass
class UnknownRecord:
    """A record of an unknown type: skipped by the NCP, preserved by hosts."""

    rtype: int
    raw: bytes

    def serialize(self) -> bytes:
        return self.raw


def record_type_of(value: Any) -> int:
    if isinstance(value, UnknownRecord):
        return value.rtype
    return int(_TYPE_OF[type(value)])


def encode_record(value: Any) -> bytes:
    """One TLV: ``u8 type, u16 len, value``."""
    body = value.serialize()
    if len(body) > 0xFFFF:
        raise CodecError("record too long")
    return struct.pack("<BH", record_type_of(value), len(body)) + body


def split_records(stream: bytes) -> list[tuple[int, bytes]]:
    """Split a record stream into raw ``(type, value)`` TLVs."""
    out = []
    i = 0
    while i < len(stream):
        if i + 3 > len(stream):
            raise CodecError("truncated record header")
        rtype, length = struct.unpack_from("<BH", stream, i)
        end = i + 3 + length
        if end > len(stream):
            raise CodecError("truncated record")
        out.append((rtype, bytes(stream[i + 3 : end])))
        i = end
    return out


def decode_record_value(rtype: int, value: bytes) -> Any:
    cls = _RECORD_CLASSES.get(rtype)
    if cls is None:
        return UnknownRecord(rtype, value)
    return cls.deserialize(value)


def decode_records(stream: bytes) -> list[Any]:
    return [decode_record_value(t, v) for t, v in split_records(stream)]


class _RecordCodec:
    """A TLV record as a field (``Record`` in the Rust codec)."""

    @staticmethod
    def make_default() -> Any:
        return None

    @staticmethod
    def pack(value: Any) -> bytes:
        return encode_record(value)

    @staticmethod
    def unpack(data: bytes, off: int) -> tuple[Any, int]:
        if off + 3 > len(data):
            raise CodecError("truncated record header")
        rtype, length = struct.unpack_from("<BH", data, off)
        end = off + 3 + length
        if end > len(data):
            raise CodecError("truncated record")
        return decode_record_value(rtype, bytes(data[off + 3 : end])), end


RECORD = _RecordCodec()


class _RecordStream:
    """The remainder of a message as a record stream."""

    @staticmethod
    def make_default() -> list:
        return []

    @staticmethod
    def pack(value: list) -> bytes:
        return b"".join(encode_record(v) if not isinstance(v, bytes) else v for v in value)

    @staticmethod
    def unpack(data: bytes, off: int) -> tuple[list, int]:
        return decode_records(data[off:]), len(data)


RECORD_STREAM = _RecordStream()


def end_record(tlvs: list[bytes]) -> EndRecord:
    """The ``END`` record over already-encoded TLVs."""
    return EndRecord(record_count=len(tlvs), crc32c=crc32c(b"".join(tlvs)))


def with_end(values: list[Any]) -> list[bytes]:
    """Encode ``values`` and append their ``END`` record."""
    tlvs = [encode_record(v) for v in values]
    return [*tlvs, encode_record(end_record(tlvs))]
