"""Link frames (spec 5.2-5.4): header, CRC, COBS wire form and frame bodies."""

from __future__ import annotations

import dataclasses
import enum
import struct

from . import cobs
from .crc import crc32c

LINK_VERSION = 1
HEADER_LEN = 8
CRC_LEN = 4
MAX_PAYLOAD = 640
MAX_DECODED_FRAME = HEADER_LEN + MAX_PAYLOAD + CRC_LEN

CTRL_POLL = 0x20
CTRL_RETX = 0x10


class FrameType(enum.IntEnum):
    DATA = 0
    ACK = 1
    NAK = 2
    RESET_REQ = 3
    RESET_ACK = 4
    REJECT = 5


class Role(enum.IntEnum):
    HOST = 0
    NCP = 1


class ResetReason(enum.IntEnum):
    POWER_ON = 0
    PEER_TIMEOUT = 1
    PROTOCOL_ERROR = 2
    RETRY_EXHAUSTED = 3
    HOST_OPEN = 4
    PEER_REQUESTED = 5
    WATCHDOG = 6
    FIRMWARE_UPDATE = 7


class RejectReason(enum.IntEnum):
    NO_CREDIT = 1
    TOO_LONG = 2
    UNKNOWN_ENDPOINT = 3
    UNSUPPORTED = 4
    WINDOW_VIOLATION = 5
    STALE_EPOCH = 6
    NOT_IN_SESSION = 7


class FrameError(ValueError):
    """A decoded frame failed validation."""

    def __init__(self, kind: str, value: int | None = None) -> None:
        super().__init__(kind if value is None else f"{kind} {value}")
        self.kind = kind
        self.value = value

    @property
    def is_noise(self) -> bool:
        """Length and CRC errors are line noise; version/type errors are bugs."""
        return self.kind in ("length", "crc")


@dataclasses.dataclass
class Header:
    ftype: FrameType
    epoch: int = 0
    endpoint: int = 0
    seq: int = 0
    ack: int = 0
    ep_seq: int = 0
    poll: bool = False
    retx: bool = False

    def ctrl(self) -> int:
        return (
            (LINK_VERSION << 6)
            | (CTRL_POLL if self.poll else 0)
            | (CTRL_RETX if self.retx else 0)
            | int(self.ftype)
        )

    def to_bytes(self, length: int) -> bytes:
        return struct.pack(
            "<BBBBBBH",
            self.ctrl(),
            self.epoch,
            self.endpoint,
            self.seq,
            self.ack,
            self.ep_seq,
            length,
        )


@dataclasses.dataclass
class Frame:
    header: Header
    payload: bytes


def encode_frame(header: Header, payload: bytes = b"") -> bytes:
    """Decoded frame: header + payload + CRC-32C."""
    if len(payload) > MAX_PAYLOAD:
        raise ValueError("payload too long")
    body = header.to_bytes(len(payload)) + bytes(payload)
    return body + struct.pack("<I", crc32c(body))


def encode_wire(header: Header, payload: bytes = b"", lead_zero: bool = False) -> bytes:
    """Wire bytes: optional leading ``0x00``, COBS, delimiter."""
    enc = cobs.encode(encode_frame(header, payload)) + b"\x00"
    return b"\x00" + enc if lead_zero else enc


def raw_header(decoded: bytes) -> bytes | None:
    return decoded[:HEADER_LEN] if len(decoded) >= HEADER_LEN else None


def parse(decoded: bytes) -> Frame:
    """Validate a decoded frame (length, CRC, version, type), in that order."""
    if len(decoded) < HEADER_LEN + CRC_LEN:
        raise FrameError("length")
    (length,) = struct.unpack_from("<H", decoded, 6)
    if len(decoded) != HEADER_LEN + length + CRC_LEN:
        raise FrameError("length")
    end = HEADER_LEN + length
    (rx_crc,) = struct.unpack_from("<I", decoded, end)
    if crc32c(decoded[:end]) != rx_crc:
        raise FrameError("crc")
    ctrl = decoded[0]
    if ctrl >> 6 != LINK_VERSION:
        raise FrameError("version", ctrl >> 6)
    try:
        ftype = FrameType(ctrl & 0x0F)
    except ValueError:
        raise FrameError("type", ctrl & 0x0F) from None
    return Frame(
        Header(
            ftype=ftype,
            epoch=decoded[1],
            endpoint=decoded[2],
            seq=decoded[3],
            ack=decoded[4],
            ep_seq=decoded[5],
            poll=bool(ctrl & CTRL_POLL),
            retx=bool(ctrl & CTRL_RETX),
        ),
        bytes(decoded[HEADER_LEN:end]),
    )


def session_epoch(host_cookie: int, ncp_cookie: int) -> int:
    """``1 + crc32c(le32(host) || le32(ncp)) mod 255`` (spec 5.5)."""
    return 1 + crc32c(struct.pack("<II", host_cookie, ncp_cookie)) % 255


@dataclasses.dataclass
class ResetBody:
    cookie: int
    peer_cookie: int
    role: int
    link_version: int = LINK_VERSION
    rx_window: int = 32
    reason: int = 0
    rx_mtu: int = MAX_PAYLOAD
    ack_delay_us: int = 1000
    keepalive_ms: int = 500
    link_timeout_ms: int = 3000
    credits: list[tuple[int, int]] = dataclasses.field(default_factory=list)

    FIXED_LEN = 21

    def to_bytes(self) -> bytes:
        out = struct.pack(
            "<IIBBBBHHHHB",
            self.cookie,
            self.peer_cookie,
            self.role,
            self.link_version,
            self.rx_window,
            self.reason,
            self.rx_mtu,
            self.ack_delay_us,
            self.keepalive_ms,
            self.link_timeout_ms,
            len(self.credits),
        )
        return out + b"".join(struct.pack("<BB", e, c) for e, c in self.credits)

    @classmethod
    def parse(cls, payload: bytes) -> ResetBody:
        if len(payload) < cls.FIXED_LEN:
            raise ValueError("truncated RESET body")
        fields = struct.unpack_from("<IIBBBBHHHHB", payload)
        n = fields[-1]
        raw = payload[cls.FIXED_LEN : cls.FIXED_LEN + 2 * n]
        if len(raw) != 2 * n:
            raise ValueError("truncated RESET credits")
        credits = [(raw[i], raw[i + 1]) for i in range(0, len(raw), 2)]
        return cls(*fields[:-1], credits=credits)


@dataclasses.dataclass
class AckBody:
    sack: int = 0
    nbad: int = 0
    credits: list[tuple[int, int]] = dataclasses.field(default_factory=list)

    def to_bytes(self) -> bytes:
        out = struct.pack("<IBB", self.sack, self.nbad, len(self.credits))
        return out + b"".join(struct.pack("<BB", e, c) for e, c in self.credits)

    @classmethod
    def parse(cls, payload: bytes) -> AckBody:
        if len(payload) < 6:
            raise ValueError("truncated ACK body")
        sack, nbad, n = struct.unpack_from("<IBB", payload)
        raw = payload[6 : 6 + 2 * n]
        if len(raw) != 2 * n:
            raise ValueError("truncated ACK credits")
        return cls(sack, nbad, [(raw[i], raw[i + 1]) for i in range(0, len(raw), 2)])


@dataclasses.dataclass
class RejectBody:
    seq: int
    endpoint: int
    ep_seq: int
    reason: int

    def to_bytes(self) -> bytes:
        return bytes((self.seq, self.endpoint, self.ep_seq, self.reason))

    @classmethod
    def parse(cls, payload: bytes) -> RejectBody:
        if len(payload) < 4:
            raise ValueError("truncated REJECT body")
        return cls(payload[0], payload[1], payload[2], payload[3])
