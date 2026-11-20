"""Consistent Overhead Byte Stuffing (spec 5.1).

Encoders emit the minimal form: data that ends exactly after a full 254-byte
block is closed by that block's ``0xFF`` code, without a trailing empty
``0x01`` block. Decoders also accept the non-minimal form.
"""

from __future__ import annotations

import enum

#: Largest encoded frame accepted by a receiver (8 + 640 + 4 decoded bytes).
MAX_ENCODED_FRAME = 656


class CobsError(ValueError):
    """Malformed COBS data."""


def max_encoded_len(n: int) -> int:
    """Worst-case encoded size of ``n`` raw bytes (without the delimiter)."""
    return n + max(1, (n + 253) // 254) if n else 1


def encode(data: bytes | bytearray | memoryview) -> bytes:
    """Encode ``data`` (no delimiter is appended)."""
    data = bytes(data)
    out = bytearray()
    n = len(data)
    start = 0
    while True:
        # A block holds up to 254 non-zero bytes; it is closed by a zero in
        # the data (code = len + 1) or by being full (code 0xFF, no zero).
        zero = data.find(0, start, min(n, start + 254))
        if zero >= 0:
            out.append(zero - start + 1)
            out += data[start:zero]
            start = zero + 1
            if start == n:
                out.append(1)  # the data ends with a zero: empty last block
                return bytes(out)
            continue
        end = min(n, start + 254)
        out.append(end - start + 1)
        out += data[start:end]
        start = end
        if start >= n:
            return bytes(out)


def decode(data: bytes | bytearray | memoryview) -> bytes:
    """Decode one COBS frame (without its delimiter)."""
    data = bytes(data)
    out = bytearray()
    i = 0
    n = len(data)
    if n == 0:
        raise CobsError("empty frame")
    while i < n:
        code = data[i]
        if code == 0:
            raise CobsError("zero byte inside a frame")
        end = i + code
        if end > n:
            raise CobsError("code byte points past the end of the frame")
        block = data[i + 1 : end]
        if 0 in block:
            raise CobsError("zero byte inside a frame")
        out += block
        i = end
        if code != 0xFF and i < n:
            out.append(0)
    return bytes(out)


class BadFrame(enum.Enum):
    """Why a frame was discarded by the accumulator."""

    TOO_LONG = "too_long"
    COBS = "cobs"
    LINE_ERROR = "line_error"


class Accumulator:
    """Collects bytes up to a ``0x00`` delimiter (mirrors ``zigbee-zrhp``)."""

    __slots__ = ("_buf", "_discarding", "_limit")

    def __init__(self, limit: int = MAX_ENCODED_FRAME) -> None:
        self._buf = bytearray()
        self._discarding = False
        self._limit = limit

    def reset(self) -> None:
        self._buf.clear()
        self._discarding = False

    def line_error(self) -> BadFrame:
        """Abort the current frame after a UART framing/parity/overrun error."""
        self._buf.clear()
        self._discarding = True
        return BadFrame.LINE_ERROR

    def push(self, byte: int) -> bytes | BadFrame | None:
        """Feed one byte. Returns a decoded frame, a :class:`BadFrame` or ``None``."""
        if byte == 0:
            buf = self._buf
            discarding = self._discarding
            self._buf = bytearray()
            self._discarding = False
            if discarding or not buf:
                return None
            try:
                return decode(buf)
            except CobsError:
                return BadFrame.COBS
        if self._discarding:
            return None
        if len(self._buf) >= self._limit:
            self._buf.clear()
            self._discarding = True
            return BadFrame.TOO_LONG
        self._buf.append(byte)
        return None
