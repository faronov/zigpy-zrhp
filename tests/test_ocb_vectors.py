"""OCB <-> records vectors (``ocb_roundtrip.json``, ``ocb_z2m_import.json``)."""

from __future__ import annotations

import copy

from zigpy_zrhp import messages as m
from zigpy_zrhp.ocb import ocb_to_records, records_to_ocb, restore_margins
from zigpy_zrhp.records import DeviceRecord, decode_records, encode_record
from zigpy_zrhp.sim.ncp import SimNcp, apply_restore
from zigpy_zrhp.types import FC_STRIDE, Kind

from .conftest import load_vector

RT = load_vector("ocb_roundtrip.json")
Z2M = load_vector("ocb_z2m_import.json")


def test_roundtrip_restore_records() -> None:
    recs = ocb_to_records(RT["input_ocb"])
    assert [encode_record(r).hex() for r in recs] == [r["hex"] for r in RT["restore"]["records"]]


def test_roundtrip_restore_messages() -> None:
    recs = ocb_to_records(RT["input_ocb"])
    msgs = RT["restore"]["messages"]
    r = RT["restore"]
    begin = m.BkpRestoreBeginReq(
        flags=0x01,
        nwk_margin=r["nwk_margin"],
        aps_margin=r["aps_margin"],
        expected_records=len(recs),
    )
    assert (
        m.Message(Kind.REQUEST, m.Id.BKP_RESTORE_BEGIN, 0x0201, begin.serialize()).serialize().hex()
        == msgs["begin"]
    )
    put = m.BkpRestorePutReq(txn=1, records=b"".join(encode_record(x) for x in recs))
    assert (
        m.Message(Kind.REQUEST, m.Id.BKP_RESTORE_PUT, 0x0202, put.serialize()).serialize().hex()
        == msgs["put"]
    )
    commit = m.BkpRestoreCommitReq(txn=1)
    assert (
        m.Message(Kind.REQUEST, m.Id.BKP_RESTORE_COMMIT, 0x0203, commit.serialize())
        .serialize()
        .hex()
        == msgs["commit"]
    )
    # Responses decode to the documented values.
    for key, mid in (
        ("begin_rsp", m.Id.BKP_RESTORE_BEGIN),
        ("put_rsp", m.Id.BKP_RESTORE_PUT),
        ("commit_rsp", m.Id.BKP_RESTORE_COMMIT),
    ):
        (msg,) = m.parse_batch(bytes.fromhex(msgs[key]))
        status, body = m.decode_response(mid, msg.payload)
        assert status == 0
        assert m.encode_response(body) == msg.payload
    (msg,) = m.parse_batch(bytes.fromhex(msgs["commit_rsp"]))
    _, body = m.decode_response(m.Id.BKP_RESTORE_COMMIT, msg.payload)
    st = r["ncp_state"]
    assert (body.nwk_fc_start, body.aps_fc_start) == (st["nwk_fc_start"], st["aps_fc_start"])
    assert (body.link_keys_on_ncp, body.link_keys_host_backed, body.children) == (
        st["link_keys_on_ncp"],
        st["link_keys_host_backed"],
        st["children"],
    )


def test_roundtrip_ncp_model_and_export() -> None:
    r = RT["restore"]
    recs = ocb_to_records(RT["input_ocb"])
    model = apply_restore(recs, r["nwk_margin"], r["aps_margin"])
    assert model.nwk_fc_start == r["ncp_state"]["nwk_fc_start"]
    assert model.aps_fc_start == r["ncp_state"]["aps_fc_start"]
    assert model.nwk_fc_start + FC_STRIDE == r["ncp_state"]["nwk_fc_limit"]
    assert model.aps_fc_start + FC_STRIDE == r["ncp_state"]["aps_fc_limit"]
    exported = [decode_records(bytes.fromhex(x["hex"]))[0] for x in RT["export"]["records"]]
    out = records_to_ocb(
        exported,
        source="zigbee-rs-reference@spec-v1",
        creation_time="2026-11-15T12:00:00+00:00",
        passthrough_stack_specific={},
    )
    assert out == RT["output_ocb"]
    # Property 1: the output converts back to byte-identical DEVICE records.
    again = ocb_to_records(out)
    assert [encode_record(x) for x in again if isinstance(x, DeviceRecord)] == [
        encode_record(x) for x in exported if isinstance(x, DeviceRecord)
    ]
    # Property 2: zero-margin restore of the output starts at the exported limits.
    m2 = apply_restore(again, 0, 0)
    assert (m2.nwk_fc_start, m2.aps_fc_start) == (
        r["ncp_state"]["nwk_fc_limit"],
        r["ncp_state"]["aps_fc_limit"],
    )


def test_sim_ncp_export_matches_vector() -> None:
    """The simulator's restore+export reproduces the exported records byte for byte."""
    r = RT["restore"]
    recs = ocb_to_records(RT["input_ocb"])
    sim = SimNcp(ieee=bytes.fromhex("3c2b1afeffb1b3f4"))
    sim.table_epoch = RT["export"]["table_epoch"] - 1
    sim.host_caps = 1
    sim.restore = {
        "txn": 1,
        "req": m.BkpRestoreBeginReq(
            flags=1, nwk_margin=r["nwk_margin"], aps_margin=r["aps_margin"]
        ),
        "records": recs,
    }
    sim.driver = None
    sim._h_bkp_restore_commit(
        m.BkpRestoreCommitReq(txn=1), m.Message(Kind.REQUEST, m.Id.BKP_RESTORE_COMMIT, 1)
    )
    exported = sim.export_records(keys=True, devices=True)
    assert [encode_record(x).hex() for x in exported] == [x["hex"] for x in RT["export"]["records"]]


def test_z2m_import() -> None:
    ocb = copy.deepcopy(Z2M["input_ocb"])
    recs = ocb_to_records(ocb)
    assert [encode_record(r).hex() for r in recs] == [r["hex"] for r in Z2M["records"]]
    nwk_margin, aps_margin = restore_margins(ocb, nwk_margin=Z2M["nwk_margin"])
    assert (nwk_margin, aps_margin) == (Z2M["nwk_margin"], Z2M["aps_margin"])
    model = apply_restore(recs, nwk_margin, aps_margin)
    assert (model.nwk_fc_start, model.aps_fc_start) == (
        Z2M["ncp_state"]["nwk_fc_start"],
        Z2M["ncp_state"]["aps_fc_start"],
    )
    assert restore_margins(RT["input_ocb"]) == (0, 10_000)
