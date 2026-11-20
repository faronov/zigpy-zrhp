"""CRC-32C (Castagnoli), spec 5.2.

Reflected polynomial ``0x82F63B78``, init ``0xFFFFFFFF``, xorout ``0xFFFFFFFF``.
The check value of ``b"123456789"`` is ``0xE3069283``.
"""

from __future__ import annotations

_POLY = 0x82F63B78


def _make_table() -> tuple[int, ...]:
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ _POLY if crc & 1 else crc >> 1
        table.append(crc)
    return tuple(table)


_TABLE = _make_table()


def crc32c_update(crc: int, data: bytes | bytearray | memoryview) -> int:
    """Continue a raw (non-inverted) CRC register over ``data``."""
    table = _TABLE
    for b in data:
        crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc


def crc32c(data: bytes | bytearray | memoryview, crc: int = 0) -> int:
    """CRC-32C of ``data``; ``crc`` continues a previous result."""
    return crc32c_update(crc ^ 0xFFFFFFFF, data) ^ 0xFFFFFFFF


try:  # pragma: no cover - optional native acceleration
    import google_crc32c as _native  # type: ignore[import-not-found]

    if _native.implementation == "c":

        def crc32c(  # type: ignore[no-redef]
            data: bytes | bytearray | memoryview, crc: int = 0
        ) -> int:
            return _native.extend(crc, bytes(data))

except ImportError:  # pragma: no cover
    pass
