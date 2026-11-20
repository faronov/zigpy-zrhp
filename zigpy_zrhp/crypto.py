"""Zigbee AES-MMO hash and keyed hash (install codes, EZSP hashed TCLK)."""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _aes_ecb(key: bytes, block: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def aes_mmo(data: bytes) -> bytes:
    """Matyas-Meyer-Oseas hash with AES-128 and Zigbee padding (B.6)."""
    n = len(data)
    if n < 2**16 // 8:
        padded = data + b"\x80"
        while (len(padded) + 2) % 16:
            padded += b"\x00"
        padded += (n * 8).to_bytes(2, "big")
    else:
        padded = data + b"\x80"
        while (len(padded) + 6) % 16:
            padded += b"\x00"
        padded += (n * 8).to_bytes(4, "big") + b"\x00\x00"
    h = bytes(16)
    for i in range(0, len(padded), 16):
        block = padded[i : i + 16]
        h = bytes(a ^ b for a, b in zip(_aes_ecb(h, block), block, strict=True))
    return h


def hmac_mmo(key: bytes, message: bytes) -> bytes:
    """Zigbee keyed hash (HMAC with AES-MMO, 16-byte block)."""
    ipad = bytes(k ^ 0x36 for k in key)
    opad = bytes(k ^ 0x5C for k in key)
    return aes_mmo(opad + aes_mmo(ipad + message))


def install_code_key(code: bytes) -> bytes:
    """Link key derived from an install code including its CRC."""
    return aes_mmo(code)
