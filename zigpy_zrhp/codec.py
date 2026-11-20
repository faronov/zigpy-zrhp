"""Little-endian wire primitives and a small declarative struct layer.

Every field type is a :class:`Codec` with ``pack(value) -> bytes`` and
``unpack(data, offset) -> (value, offset)``. :class:`Struct` subclasses list
their fields in ``_fields`` and are codecs themselves, so they nest (lists of
structs, records inside messages).
"""

from __future__ import annotations

import struct
from typing import Any, ClassVar


class CodecError(ValueError):
    """Truncated or invalid wire data."""


class Codec:
    default: Any = 0

    def pack(self, value: Any) -> bytes:  # pragma: no cover - interface
        raise NotImplementedError

    def unpack(self, data: bytes, off: int) -> tuple[Any, int]:  # pragma: no cover
        raise NotImplementedError

    def make_default(self) -> Any:
        return self.default


class _Int(Codec):
    def __init__(self, fmt: str) -> None:
        self._s = struct.Struct("<" + fmt)
        self.size = self._s.size

    def pack(self, value: Any) -> bytes:
        try:
            return self._s.pack(int(value))
        except struct.error as e:
            raise CodecError(str(e)) from None

    def unpack(self, data: bytes, off: int) -> tuple[int, int]:
        end = off + self.size
        if end > len(data):
            raise CodecError("truncated")
        return self._s.unpack_from(data, off)[0], end


U8 = _Int("B")
U16 = _Int("H")
U32 = _Int("I")
U64 = _Int("Q")
I8 = _Int("b")


class Fixed(Codec):
    """A fixed-size byte array (IEEE addresses travel in on-air order)."""

    def __init__(self, size: int) -> None:
        self.size = size
        self.default = bytes(size)

    def pack(self, value: Any) -> bytes:
        value = bytes(value)
        if len(value) != self.size:
            raise CodecError(f"expected {self.size} bytes, got {len(value)}")
        return value

    def unpack(self, data: bytes, off: int) -> tuple[bytes, int]:
        end = off + self.size
        if end > len(data):
            raise CodecError("truncated")
        return bytes(data[off:end]), end


IEEE = Fixed(8)
KEY = Fixed(16)
EPID = Fixed(8)
SHA256 = Fixed(32)


class LenBytes(Codec):
    """Length-prefixed bytes (``Bytes8`` / ``Bytes16``)."""

    default = b""

    def __init__(self, len_codec: _Int) -> None:
        self._len = len_codec

    def pack(self, value: Any) -> bytes:
        value = value.encode() if isinstance(value, str) else bytes(value)
        return self._len.pack(len(value)) + value

    def unpack(self, data: bytes, off: int) -> tuple[bytes, int]:
        n, off = self._len.unpack(data, off)
        end = off + n
        if end > len(data):
            raise CodecError("truncated")
        return bytes(data[off:end]), end


LV8 = LenBytes(U8)
LV16 = LenBytes(U16)


class _Rest(Codec):
    default = b""

    def pack(self, value: Any) -> bytes:
        return value.encode() if isinstance(value, str) else bytes(value)

    def unpack(self, data: bytes, off: int) -> tuple[bytes, int]:
        return bytes(data[off:]), len(data)


REST = _Rest()


class ListOf(Codec):
    """A ``u8``-counted list."""

    def __init__(self, item: Any) -> None:
        self.item = item

    def make_default(self) -> list:
        return []

    def pack(self, value: Any) -> bytes:
        value = list(value)
        if len(value) > 255:
            raise CodecError("list too long")
        return U8.pack(len(value)) + b"".join(self.item.pack(v) for v in value)

    def unpack(self, data: bytes, off: int) -> tuple[list, int]:
        n, off = U8.unpack(data, off)
        out = []
        for _ in range(n):
            v, off = self.item.unpack(data, off)
            out.append(v)
        return out, off


class Struct:
    """Base of all wire structs, messages and records."""

    _fields: ClassVar[tuple[tuple[str, Any], ...]] = ()

    def __init__(self, **kwargs: Any) -> None:
        for name, codec in self._fields:
            if name in kwargs:
                value = kwargs.pop(name)
            else:
                value = codec.make_default()
            setattr(self, name, value)
        if kwargs:
            raise TypeError(f"{type(self).__name__}: unknown fields {sorted(kwargs)}")

    # Codec protocol on the class itself.
    @classmethod
    def make_default(cls) -> Struct:
        return cls()

    @classmethod
    def pack(cls, value: Struct) -> bytes:
        return value.serialize()

    @classmethod
    def unpack(cls, data: bytes, off: int) -> tuple[Struct, int]:
        values = {}
        for name, codec in cls._fields:
            values[name], off = codec.unpack(data, off)
        return cls(**values), off

    def serialize(self) -> bytes:
        return b"".join(codec.pack(getattr(self, name)) for name, codec in self._fields)

    @classmethod
    def deserialize(cls, data: bytes) -> Struct:
        """Decode; trailing bytes are ignored (spec 6.6 minor-version rule)."""
        value, _ = cls.unpack(bytes(data), 0)
        return value

    def as_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name, _ in self._fields}

    def replace(self, **kwargs: Any) -> Struct:
        return type(self)(**{**self.as_dict(), **kwargs})

    def __eq__(self, other: object) -> bool:
        return type(self) is type(other) and self.as_dict() == other.as_dict()  # type: ignore[union-attr]

    def __hash__(self) -> int:  # pragma: no cover - structs are mutable
        return id(self)

    def __repr__(self) -> str:
        def fmt(v: Any) -> str:
            if isinstance(v, bytes):
                return v.hex()
            if isinstance(v, int) and not isinstance(v, bool) and v > 9:
                return hex(v)
            return repr(v)

        inner = ", ".join(f"{n}={fmt(getattr(self, n))}" for n, _ in self._fields)
        return f"{type(self).__name__}({inner})"


def struct_type(name: str, base: type[Struct] = Struct, /, **fields: Any) -> type[Struct]:
    """Create a :class:`Struct` subclass with ordered ``fields``."""
    return type(name, (base,), {"_fields": tuple(fields.items()), "__module__": __name__})
