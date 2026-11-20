"""Open ZigBee Coordinator Backup (OCB) <-> ZRHP records (spec 9.1-9.3).

These are the host-side converters of ``host-protocol-vectors/generate.py``,
extended with the importer tolerances of spec 9.1 (Z2M unpadded hex, ``date``,
missing TCLK counter, pass-through of unknown ``internal``/``stack_specific``
keys).
"""

from __future__ import annotations

import copy
import logging
from typing import Any

from .records import (
    ChildInfo,
    DeviceFlags,
    DeviceRecord,
    EzspHashedTclkRecord,
    GpProxyRecord,
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
    decode_record_value,
    encode_record,
    end_record,
    record_type_of,
)
from .types import FC_STRIDE

LOGGER = logging.getLogger(__name__)

TCLK_DEFAULT = b"ZigBeeAlliance09"
#: Host APS margin when a backup carries no TCLK frame counter (spec 9.4).
APS_UNKNOWN_TCLK_MARGIN = 1 << 20
OCB_FORMAT = "zigpy/open-coordinator-backup"

#: Child-info defaults when OCB has no capability (spec 9.3).
DEFAULT_CHILD_CAPABILITY = 0x80
DEFAULT_CHILD_TIMEOUT_EXP = 8

#: ``internal`` keys this converter interprets; others are passed through.
_KNOWN_INTERNAL = {
    "node",
    "network",
    "link_key_seqs",
    "creation_time",
    "date",
    "route_table",
    "tx_power",
}


def ieee_wire(text: str) -> bytes:
    """OCB big-endian hex -> on-air (little-endian) bytes."""
    return bytes.fromhex(text.replace(":", "").zfill(16))[::-1]


def ieee_text(raw: bytes) -> str:
    """On-air bytes -> OCB big-endian hex."""
    return bytes(raw)[::-1].hex()


def hex16(text: str) -> int:
    """A big-endian 16-bit hex field; Z2M omits leading zeros (``"a62"``)."""
    return int(text.zfill(4), 16)


def channels_to_mask(channels: list[int]) -> int:
    mask = 0
    for channel in channels:
        if not 11 <= channel <= 26:
            raise ValueError(f"invalid channel {channel}")
        mask |= 1 << channel
    return mask


def mask_to_channels(mask: int) -> list[int]:
    return [c for c in range(11, 27) if mask & (1 << c)]


def tclk_counter_known(ocb: dict[str, Any]) -> bool:
    """``False`` for backups without a TCLK frame counter (Z2M, spec 9.1)."""
    network = ocb.get("metadata", {}).get("internal", {}).get("network", {})
    tclk = network.get("tc_link_key")
    return isinstance(tclk, dict) and "frame_counter" in tclk


def restore_margins(ocb: dict[str, Any], *, nwk_margin: int = 0) -> tuple[int, int]:
    """``(nwk_margin, aps_margin)`` for a restore of ``ocb`` (spec 9.4 rule 6)."""
    aps = 10_000 if tclk_counter_known(ocb) else APS_UNKNOWN_TCLK_MARGIN
    return nwk_margin, aps


def ocb_to_records(ocb: dict[str, Any], *, node_flags: int = 0x01) -> list[Any]:
    """Convert an OCB backup into restore records, ending with ``END``.

    ``node_flags`` bit0 marks the coordinator IEEE as an override to apply.
    """
    internal = ocb["metadata"].get("internal", {})
    node = internal.get("node", {})
    network = internal.get("network", {})
    coordinator = ieee_wire(ocb["coordinator_ieee"])
    node_nwk = hex16(node.get("nwk", "0000"))
    recs: list[Any] = [NodeRecord(ieee=coordinator, nwk=node_nwk, logical_type=0, flags=node_flags)]
    tx_power = internal.get("tx_power")
    if tx_power is not None:
        tx_power = max(-128, min(126, round(float(tx_power))))
    manager_text = network.get("nwk_manager", "0000")
    nwk_manager = hex16(manager_text)
    if nwk_manager:
        LOGGER.warning(
            "Backup has a non-zero nwk_manager %r, interpreting it as big-endian",
            manager_text,
        )
    recs.append(
        NetworkRecord(
            pan_id=hex16(ocb["pan_id"]),
            ext_pan_id=ieee_wire(ocb["extended_pan_id"]),
            channel=ocb["channel"],
            channel_mask=channels_to_mask(ocb["channel_mask"]),
            nwk_update_id=ocb["nwk_update_id"],
            nwk_manager=nwk_manager,
            security_level=ocb["security_level"],
            tx_power=0x7F if tx_power is None else tx_power,
        )
    )
    key = ocb["network_key"]
    recs.append(
        NetworkKeyRecord(
            key=bytes.fromhex(key["key"]),
            seq=key.get("sequence_number", 0) or 0,
            tx_counter=key.get("frame_counter", 0) or 0,
            flags=0x01,
        )
    )
    tclk = network.get("tc_link_key")
    tc_key = bytes.fromhex(tclk["key"]) if tclk else TCLK_DEFAULT
    tc_counter = (tclk.get("frame_counter", 0) or 0) if tclk else 0
    tc_address = ieee_wire(network["tc_address"]) if network.get("tc_address") else coordinator
    if tc_address == b"\xff" * 8 or tc_address == bytes(8):
        tc_address = coordinator
    stack_specific = ocb.get("stack_specific") or {}
    hashed = (stack_specific.get("ezsp") or {}).get("hashed_tclk")
    recs.append(
        TcLinkKeyRecord(
            key=tc_key,
            tc_ieee=tc_address,
            tx_counter=tc_counter,
            flags=0x01 if hashed else 0x00,
        )
    )
    if hashed:
        recs.append(EzspHashedTclkRecord(seed=bytes.fromhex(hashed)))
    zrs = stack_specific.get("zigbee_rs")
    if zrs:
        recs.append(
            RsParamsRecord(
                fc_stride=zrs.get("frame_counter_stride", FC_STRIDE),
                table_epoch=zrs.get("table_epoch", 0),
                nwk_fc_limit=zrs.get("nwk_frame_counter_limit", 0),
                aps_fc_limit=zrs.get("aps_frame_counter_limit", 0),
                flags=0x01 if zrs.get("host_backed_tables") else 0x00,
            )
        )
    seqs = {k.lower(): v for k, v in internal.get("link_key_seqs", {}).items()}
    for dev in sorted(ocb["devices"], key=lambda d: d["ieee_address"].lower()):
        recs.append(_device_record(dev, seqs))
    if zrs:
        for value in zrs.get("gp_proxy_table", []):
            recs.append(decode_record_value(RecordType.GP_PROXY, bytes.fromhex(value)))
        for value in zrs.get("gp_sink_table", []):
            recs.append(decode_record_value(RecordType.GP_SINK, bytes.fromhex(value)))
    recs.append(end_record([encode_record(r) for r in recs]))
    return recs


def _device_record(dev: dict[str, Any], seqs: dict[str, int]) -> DeviceRecord:
    ieee = dev["ieee_address"].lower()
    nwk_text = dev.get("nwk_address")
    nwk = None if nwk_text is None else hex16(nwk_text)
    is_child = dev.get("is_child", True)
    flags = (DeviceFlags.IS_CHILD if is_child else 0) | (
        DeviceFlags.NWK_VALID if nwk is not None else 0
    )
    child = (
        ChildInfo(
            capability=dev.get("capability", DEFAULT_CHILD_CAPABILITY),
            timeout_exp=dev.get("timeout_exp", DEFAULT_CHILD_TIMEOUT_EXP),
        )
        if is_child
        else None
    )
    link = None
    if dev.get("link_key"):
        lk = dev["link_key"]
        link = LinkBlock(
            key=bytes.fromhex(lk["key"]),
            key_seq=seqs.get(ieee, 0),
            attrs=KeyAttrs.VERIFIED,
            origin=KeyOrigin.IMPORTED,
            tx_counter=lk.get("tx_counter", 0) or 0,
            rx_floor=lk.get("rx_counter", 0) or 0,
        )
    return DeviceRecord(
        ieee=ieee_wire(ieee),
        nwk=0xFFFF if nwk is None else nwk,
        flags=int(flags),
        child=child,
        link=link,
    )


def records_to_ocb(
    records: list[Any],
    *,
    source: str,
    creation_time: str,
    passthrough_stack_specific: dict[str, Any] | None = None,
    passthrough_internal: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Convert exported records into an OCB backup (``END`` is checked)."""
    if not records or record_type_of(records[-1]) != RecordType.END:
        raise ValueError("record stream does not end with END")
    end = records[-1]
    body = records[:-1]
    expect = end_record([encode_record(r) for r in body])
    if (end.record_count, end.crc32c) != (expect.record_count, expect.crc32c):
        raise ValueError("END record count or CRC mismatch")

    stack_specific = copy.deepcopy(passthrough_stack_specific or {})
    devices: list[dict[str, Any]] = []
    seqs: dict[str, int] = {}
    out: dict[str, Any] = {}
    tclk: dict[str, Any] = {"key": TCLK_DEFAULT.hex(), "frame_counter": 0}
    tc_address = None
    node_nwk = 0
    tx_power = 0x7F
    gp_proxy: list[str] = []
    gp_sink: list[str] = []
    zrs: dict[str, Any] | None = None
    for rec in body:
        if isinstance(rec, NodeRecord):
            out["coordinator_ieee"] = ieee_text(rec.ieee)
            node_nwk = rec.nwk
        elif isinstance(rec, NetworkRecord):
            out.update(
                pan_id=f"{rec.pan_id:04x}",
                extended_pan_id=ieee_text(rec.ext_pan_id),
                channel=rec.channel,
                channel_mask=mask_to_channels(rec.channel_mask),
                nwk_update_id=rec.nwk_update_id,
                security_level=rec.security_level,
            )
            tx_power = rec.tx_power
        elif isinstance(rec, NetworkKeyRecord):
            out["network_key"] = {
                "key": rec.key.hex(),
                "sequence_number": rec.seq,
                "frame_counter": rec.tx_counter,
            }
        elif isinstance(rec, TcLinkKeyRecord):
            tclk = {"key": rec.key.hex(), "frame_counter": rec.tx_counter}
            tc_address = ieee_text(rec.tc_ieee)
        elif isinstance(rec, EzspHashedTclkRecord):
            stack_specific.setdefault("ezsp", {})["hashed_tclk"] = rec.seed.hex()
        elif isinstance(rec, RsParamsRecord):
            zrs = {
                "version": 1,
                "frame_counter_stride": rec.fc_stride,
                "table_epoch": rec.table_epoch,
                "nwk_frame_counter_limit": rec.nwk_fc_limit,
                "aps_frame_counter_limit": rec.aps_fc_limit,
                "host_backed_tables": bool(rec.flags & 0x01),
            }
        elif isinstance(rec, DeviceRecord):
            ieee = ieee_text(rec.ieee)
            dev: dict[str, Any] = {
                "ieee_address": ieee,
                "nwk_address": f"{rec.nwk:04x}" if rec.nwk_valid else None,
                "is_child": rec.is_child,
            }
            if rec.link is not None:
                dev["link_key"] = {
                    "key": rec.link.key.hex(),
                    "tx_counter": rec.link.tx_counter,
                    "rx_counter": rec.link.rx_floor,
                }
                seqs[ieee] = rec.link.key_seq
            devices.append(dev)
        elif isinstance(rec, GpProxyRecord):
            gp_proxy.append(rec.serialize().hex())
        elif isinstance(rec, GpSinkRecord):
            gp_sink.append(rec.serialize().hex())
        elif isinstance(rec, UnknownRecord):
            LOGGER.debug("Skipping unknown record type 0x%02X in export", rec.rtype)
    if "network_key" not in out:
        # Key export locked: an incomplete backup (zigpy's is_complete() fails).
        out["network_key"] = {
            "key": "ff" * 16,
            "sequence_number": 0,
            "frame_counter": zrs["nwk_frame_counter_limit"] if zrs else 0,
        }
    if zrs is not None:
        zrs["gp_proxy_table"] = gp_proxy
        zrs["gp_sink_table"] = gp_sink
        stack_specific["zigbee_rs"] = zrs
    internal: dict[str, Any] = {
        "creation_time": creation_time,
        "node": {
            "ieee": out["coordinator_ieee"],
            "nwk": f"{node_nwk:04x}",
            "type": "coordinator",
        },
        "network": {
            "tc_link_key": tclk,
            "tc_address": tc_address or out["coordinator_ieee"],
            "nwk_manager": "0000",
        },
        "link_key_seqs": seqs,
    }
    if tx_power != 0x7F:
        internal["tx_power"] = tx_power
    for k, v in (passthrough_internal or {}).items():
        if k not in _KNOWN_INTERNAL:
            internal[k] = copy.deepcopy(v)
    return {
        "metadata": {
            "version": 1,
            "format": OCB_FORMAT,
            "source": source,
            "internal": internal,
        },
        "stack_specific": stack_specific,
        **{
            k: out[k]
            for k in (
                "coordinator_ieee",
                "pan_id",
                "extended_pan_id",
                "nwk_update_id",
                "security_level",
                "channel",
                "channel_mask",
                "network_key",
            )
        },
        "devices": sorted(devices, key=lambda d: d["ieee_address"]),
    }


def passthrough_internal(ocb: dict[str, Any]) -> dict[str, Any]:
    """Unknown ``metadata.internal`` keys to re-emit unchanged (spec 9.1)."""
    internal = ocb.get("metadata", {}).get("internal", {})
    return {k: v for k, v in internal.items() if k not in _KNOWN_INTERNAL}
