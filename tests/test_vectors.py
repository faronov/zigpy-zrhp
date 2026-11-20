"""Byte-exact tests against the shared ZRHP vectors (spec 14.1).

The JSON files in ``tests/vectors`` are copies of
``zigbee-rs/docs/book/src/advanced/host-protocol-vectors``;
``scripts/sync_vectors.py --check`` compares them with upstream.
"""

from __future__ import annotations

import struct

import pytest

from zigpy_zrhp import cobs, frame, messages as m
from zigpy_zrhp.crc import crc32c
from zigpy_zrhp.crypto import aes_mmo, hmac_mmo
from zigpy_zrhp.frame import AckBody, FrameType, Header, RejectBody, ResetBody
from zigpy_zrhp.ocb import ieee_wire
from zigpy_zrhp.records import (
    GpdId,
    GpSinkRecord,
    GpTranslation,
    GpTranslationRecord,
    decode_records,
    encode_record,
)
from zigpy_zrhp.types import Kind

from .conftest import load_vector


def test_crc32c() -> None:
    data = load_vector("crc32c.json")
    for v in data["vectors"]:
        raw = v["input_ascii"].encode() if "input_ascii" in v else bytes.fromhex(v["input_hex"])
        assert crc32c(raw) == int(v["crc32c"], 16)


def test_cobs_encode_decode() -> None:
    data = load_vector("cobs.json")
    for v in data["vectors"]:
        raw = bytes.fromhex(v["raw_hex"])
        enc = bytes.fromhex(v["encoded_hex"])
        assert len(raw) == v["raw_len"]
        assert len(enc) == v["encoded_len"]
        assert cobs.encode(raw) == enc, v["name"]
        assert cobs.decode(enc) == raw, v["name"]
        acc = cobs.Accumulator(limit=1024)
        results = [acc.push(b) for b in enc + b"\x00"]
        assert results[-1] == raw
    for v in data["decode_only"]:
        assert cobs.decode(bytes.fromhex(v["encoded_hex"])) == bytes.fromhex(v["raw_hex"])


def test_session_epoch() -> None:
    s = load_vector("link_frames.json")["session"]
    assert frame.session_epoch(int(s["host_cookie"], 16), int(s["ncp_cookie"], 16)) == s["epoch"]


def _header_for(v: dict) -> Header:
    f = v["fields"]
    flags = f.get("flags", 0)
    return Header(
        FrameType(v["type"]),
        epoch=f.get("epoch", 0),
        endpoint=f.get("endpoint", 0),
        seq=f.get("seq", 0),
        ack=f.get("ack", 0),
        ep_seq=f.get("ep_seq", 0),
        poll=bool(flags & frame.CTRL_POLL),
        retx=bool(flags & frame.CTRL_RETX),
    )


def _typed_payload(name: str) -> bytes | None:
    """Rebuild link frame payloads from typed bodies where they are link bodies."""
    credits = [(1, 4), (2, 8), (3, 4), (4, 4), (5, 2)]
    if name == "reset_req_host":
        return ResetBody(
            cookie=0x1A2B3C4D, peer_cookie=0, role=0, rx_window=32, reason=4, credits=credits
        ).to_bytes()
    if name == "reset_ack_ncp":
        return ResetBody(
            cookie=0xC0FFEE01,
            peer_cookie=0x1A2B3C4D,
            role=1,
            rx_window=16,
            reason=0,
            credits=[(1, 4), (2, 8), (3, 4), (4, 2), (5, 0)],
        ).to_bytes()
    if name in ("ack_plain", "keepalive_poll"):
        return AckBody(0, 0, []).to_bytes()
    if name == "nak_gap":
        return AckBody(0b11, 0, []).to_bytes()
    if name == "nak_crc_error":
        return AckBody(0, 1, []).to_bytes()
    if name == "ack_with_credits":
        return AckBody(0, 0, [(2, 17), (4, 6)]).to_bytes()
    if name == "reject_no_credit":
        return RejectBody(7, 4, 6, 1).to_bytes()
    if name == "data_negotiate":
        body = m.SysNegotiateReq(major_min=1, major_max=1, host_caps=0, name=b"zigpy-zrs/0.1")
        return m.Message(Kind.REQUEST, m.Id.SYS_NEGOTIATE, 1, body.serialize()).serialize()
    if name in ("data_batch_two_messages", "data_retransmit_poll"):
        return (
            m.Message(
                Kind.REQUEST, m.Id.SYS_ECHO, 2, m.SysEchoReq(data=b"ping").serialize()
            ).serialize()
            + m.Message(Kind.REQUEST, m.Id.SYS_GET_STATUS, 3).serialize()
        )
    return None


@pytest.mark.parametrize("v", load_vector("link_frames.json")["vectors"], ids=lambda v: v["name"])
def test_link_frames(v: dict) -> None:
    payload = bytes.fromhex(v["payload_hex"])
    typed = _typed_payload(v["name"])
    if typed is not None:
        assert typed == payload
    h = _header_for(v)
    decoded = frame.encode_frame(h, payload)
    assert decoded.hex() == v["decoded_hex"]
    assert struct.unpack("<I", decoded[-4:])[0] == int(v["crc32c"], 16)
    wire = frame.encode_wire(h, payload)
    assert wire.hex() == v["wire_hex"]
    assert len(wire) <= cobs.MAX_ENCODED_FRAME + 1
    # Parse back.
    acc = cobs.Accumulator()
    out = [acc.push(b) for b in wire]
    parsed = frame.parse(out[-1])
    assert parsed.header == h
    assert parsed.payload == payload
    if h.ftype in (FrameType.RESET_REQ, FrameType.RESET_ACK):
        assert ResetBody.parse(payload).to_bytes() == payload
    elif h.ftype in (FrameType.ACK, FrameType.NAK):
        assert AckBody.parse(payload).to_bytes() == payload
    elif h.ftype is FrameType.REJECT:
        assert RejectBody.parse(payload).to_bytes() == payload
    elif h.ftype is FrameType.DATA and v["name"] != "data_max_payload":
        assert b"".join(x.serialize() for x in m.parse_batch(payload)) == payload


GPD_KEY = bytes.fromhex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf")
SINK_REC = GpSinkRecord(
    gpd_id=GpdId.srcid(0x293C9879),
    device_id=0x02,
    communication_mode=2,
    group=0x0B84,
    assigned_alias=0xFFFF,
    flags=0x09,
    security_level=3,
    key_type=4,
    key=GPD_KEY,
    frame_counter=4448,
    groupcast_radius=0,
)
TOGGLE_OFF = GpTranslation(gpd_command=0x22, endpoint=1, cluster=0x0006, zcl_command=0x00)
STEP_DERIVED = GpTranslation(
    gpd_command=0x32, endpoint=1, cluster=0x0008, zcl_command=0x06, payload_len=0xFE
)
MOVE_TO_LEVEL = GpTranslation(
    gpd_command=0x21, endpoint=2, cluster=0x0008, zcl_command=0x04, payload=b"\x80\x0a\x00"
)
DEVICE_HEX = "0526000c0b0afeff142e84214f0aa0a1a2a3a4a5a6a7a8a9aaabacadaeaf000203c836000003000000"


def _built(name: str):
    """The typed object each message vector must serialize to."""
    if name == "sys_negotiate_req":
        return m.SysNegotiateReq(major_min=1, major_max=1, host_caps=0, name=b"zigpy-zrs/0.1")
    if name == "sys_negotiate_rsp":
        caps = {
            1: 16,
            2: 64,
            3: 256,
            4: 512,
            5: 128,
            6: 100,
            7: 1024,
            8: 8,
            13: 16,
            14: 8,
            15: 16,
            16: 8,
            17: 8,
            18: 256,
        }
        return m.SysNegotiateRsp(
            major=1,
            minor=0,
            ncp_caps=0x1787FB,
            capacities=[m.Capacity(id=k, value=v) for k, v in caps.items()],
            fw=b"0.1.0",
            build_id=bytes.fromhex("0123456789abcdef"),
            chip=1,
        )
    if name == "evt_ncp_ready":
        return m.EvtNcpReady(
            ncp_cookie=0xC0FFEE01,
            reset_reason=1,
            network_state=2,
            table_epoch=7,
            nwk_fc_limit=2011024,
            aps_fc_limit=14024,
            dirty_writebacks=0,
            dropped_indications=0,
        )
    if name == "aps_data_request_unicast":
        return m.ApsDataRequest(
            dst_mode=m.AddrMode.NWK,
            dst=0x1A2B,
            dst_ep=1,
            src_ep=1,
            profile=0x0104,
            cluster=0x0000,
            tx_options=1,
            priority=1,
            asdu=bytes.fromhex("002a0004000500"),
        )
    if name == "aps_data_request_source_routed":
        return m.ApsDataRequest(
            dst=0x8F3E,
            dst_ep=1,
            src_ep=1,
            profile=0x0104,
            cluster=0x0006,
            tx_options=0x41,
            relays=[0x1A2B, 0x3C4D],
            asdu=bytes.fromhex("012b02"),
        )
    if name == "evt_aps_data_confirm":
        return m.EvtApsDataConfirm(
            req_tid=0x0102,
            status=0,
            zb_status=0,
            aps_counter=0x37,
            dst_nwk=0x1A2B,
            flags=1,
            elapsed_ms=23,
        )
    if name == "evt_aps_data_indication":
        return m.EvtApsDataIndication(
            dst_mode=0x02,
            dst=0x0000,
            dst_ep=1,
            src_nwk=0x8F3E,
            src_ieee=ieee_wire("00158d0004c5d6e7"),
            src_ep=1,
            profile=0x0104,
            cluster=0x0402,
            flags=0x06,
            lqi=0xB4,
            rssi=-61,
            last_hop_nwk=0x1A2B,
            aps_counter=0x5C,
            key_source=0,
            rx_time_ms=123456,
            asdu=bytes.fromhex("18050a0000293409"),
        )
    if name == "nwk_permit_join":
        return m.NwkPermitJoinReq(duration_s=254, target=0xFFFC, flags=1)
    if name == "evt_device_joined":
        return m.EvtDeviceJoined(
            nwk=0x4F21,
            ieee=ieee_wire("842e14fffe0a0b0c"),
            parent_nwk=0x1A2B,
            join_type=0,
            capability=0x80,
            decision=0,
        )
    if name == "evt_route_record":
        return m.EvtRouteRecord(
            src_nwk=0x8F3E, src_ieee=ieee_wire("00158d0004c5d6e7"), relays=[0x3C4D, 0x1A2B]
        )
    if name == "sec_add_install_code":
        return m.SecAddInstallCodeReq(
            ieee=ieee_wire("842e14fffe0a0b0c"),
            code=bytes.fromhex("88776655443322111122334455667788D490"),
        )
    if name == "sec_add_install_code_rsp":
        return m.SecAddInstallCodeRsp(derived_key=bytes.fromhex("fa8081caaa41d5ade9b5658799268b88"))
    if name == "evt_fc_checkpoint":
        return m.EvtFcCheckpoint(domain=1, key_seq=1, durable_limit=2012048, generation=7)
    if name == "tbl_lookup_req":
        return m.TblLookupReq(table=0x05, key=m.TableKey(2, 0x4F21))
    if name == "tbl_lookup_rsp":
        return m.TblLookupRsp(rev=41, record=decode_records(bytes.fromhex(DEVICE_HEX))[0])
    if name == "tbl_writeback_evict":
        return m.TblWritebackReq(
            table=0x05, reason=3, rev=57, record=decode_records(bytes.fromhex(DEVICE_HEX))[0]
        )
    if name == "sec_lock_key_export":
        return m.SecLockKeyExportReq(confirm=0x4B434F4C)
    if name == "sys_set_uart":
        return m.SysSetUartReq(baud=921600, flow=0, apply_delay_ms=50)
    if name == "evt_log_record":
        return m.EvtLogRecord(
            time_ms=5321, level=3, module=2, seq=17, text=b"zrhp: session up, window 16"
        )
    if name == "gp_sink_config_zigpy":
        return m.GpSinkConfigReq(
            mode=1, communication_mode=2, group=0x0B84, exit_mode=5, window_s=180, security_level=0
        )
    if name == "gp_sink_commissioning_enter":
        return m.GpSinkCommissioningReq(action=1, flags=1, window_s=254)
    if name == "evt_gp_commissioned":
        return m.EvtGpCommissioned(
            gpd_id=GpdId.srcid(0x293C9879), device_id=0x02, flags=0x02, record=SINK_REC
        )
    if name == "evt_gp_frame_toggle":
        return m.EvtGpFrame(
            origin=1,
            result=1,
            gpd_id=GpdId.srcid(0x293C9879),
            device_id=0x02,
            command_id=0x22,
            frame_counter=4449,
            security_level=3,
            key_type=4,
            flags=0x02,
            proxy_nwk=0xFFFF,
            gpp_gpd_link=0xFF,
            rssi=-48,
            lqi=220,
            payload=b"",
        )
    if name == "gp_pairing_configuration":
        return m.GpPairingConfigurationReq(
            dst=0x7C87,
            actions=0x0A,
            gpd_id=GpdId.srcid(0x7A6B9879),
            device_id=0x02,
            communication_mode=1,
            flags=0x0D,
            security_level=3,
            key_type=4,
            key=GPD_KEY,
            frame_counter=10,
            paired=0xFE,
        )
    if name == "gp_remote_rsp":
        return m.GpRemoteRsp(zcl_tsn=5)
    if name == "gp_translation_update":
        return m.GpTranslationUpdateReq(
            dst=0x7C87,
            action=0,
            gpd_id=GpdId.srcid(0x7A6B9879),
            translations=[TOGGLE_OFF, STEP_DERIVED, MOVE_TO_LEVEL],
        )
    if name == "gp_send_pairing":
        return m.GpSendPairingReq(
            dst=0xFFFD,
            flags=0x59,
            gpd_id=GpdId.srcid(0x7A6B9879),
            communication_mode=3,
            security_level=3,
            key_type=4,
            sink_ieee=ieee_wire("0102030405060708"),
            sink_nwk=0x7C87,
            sink_group=0,
            device_id=0x02,
            frame_counter=10,
            key=GPD_KEY,
        )
    if name == "gp_translation_request":
        return m.GpTranslationRequestReq(dst=0x7C87, start_index=0)
    if name == "gp_remote_sink_table_request":
        return m.GpRemoteSinkTableRequestReq(dst=0x7C87, index=0xFF, gpd_id=GpdId.srcid(0x7A6B9879))
    if name == "evt_gp_remote_status":
        return m.EvtGpRemoteStatus(src_nwk=0x7C87, zcl_tsn=5, command_id=0x09, zcl_status=0)
    if name == "evt_gp_remote_translation_table":
        return m.EvtGpRemoteTranslationTable(
            src_nwk=0x7C87,
            zcl_tsn=6,
            status=0,
            total=2,
            start_index=0,
            flags=0,
            records=[
                GpTranslationRecord(gpd_id=GpdId.srcid(0x7A6B9879), translation=TOGGLE_OFF),
                GpTranslationRecord(gpd_id=GpdId.srcid(0x7A6B9879), translation=STEP_DERIVED),
            ],
        )
    return None


STATUS_ONLY = {
    "aps_data_request_rsp_accepted": 0,
    "aps_data_request_rsp_busy": 2,
    "sec_lock_key_export_rsp": 0,
}


@pytest.mark.parametrize("v", load_vector("messages.json"), ids=lambda v: v["name"])
def test_messages(v: dict) -> None:
    payload = bytes.fromhex(v["payload_hex"])
    kind = Kind(v["kind"])
    msg_id = int(v["msg_id"], 16)
    msg = m.Message(kind, msg_id, v["tid"], payload)
    assert msg.serialize().hex() == v["message_hex"]
    assert m.home_endpoint(msg_id) == v["endpoint"]
    assert m.parse_batch(msg.serialize()) == [msg]

    if v["name"] in STATUS_ONLY:
        assert payload == bytes([STATUS_ONLY[v["name"]]])
        status, body = m.decode_response(msg_id, payload)
        assert status == STATUS_ONLY[v["name"]] and body is None
        return
    built = _built(v["name"])
    assert built is not None, f"no typed builder for {v['name']}"
    if kind is Kind.RESPONSE:
        assert m.encode_response(built) == payload
        status, body = m.decode_response(msg_id, payload)
        assert status == 0
        assert body == built
    else:
        assert built.serialize() == payload
        decoded = m.decode_message(msg)
        assert decoded == built
        assert decoded.serialize() == payload
    # Record payloads carried in fields.
    if "record_hex" in v["fields"]:
        assert encode_record(SINK_REC).hex() == v["fields"]["record_hex"]
    for rec_hex in v["fields"].get("records_hex", []):
        (rec,) = decode_records(bytes.fromhex(rec_hex))
        assert encode_record(rec).hex() == rec_hex


def test_install_code_key() -> None:
    (v,) = [x for x in load_vector("messages.json") if x["name"] == "sec_add_install_code_rsp"]
    code = bytes.fromhex("88776655443322111122334455667788D490")
    assert aes_mmo(code).hex() == v["fields"]["derived_key"]


def test_ezsp_hashed_tclk_candidates() -> None:
    data = load_vector("ezsp_hashed_tclk.json")
    for v in data["vectors"]:
        seed = bytes.fromhex(v["hashed_tclk"])
        assert hmac_mmo(seed, ieee_wire(v["ieee"])).hex() == v["candidate_eui64_on_air_order"]
        assert hmac_mmo(seed, bytes.fromhex(v["ieee"])).hex() == v["candidate_eui64_big_endian"]
