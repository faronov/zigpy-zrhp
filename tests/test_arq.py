"""Normative ARQ traces (``arq_scenarios.json``, spec 5.9) on a virtual clock."""

from __future__ import annotations

import pytest

from zigpy_zrhp.frame import FrameType, Role
from zigpy_zrhp.link import LinkConfig, NoSource
from zigpy_zrhp.types import Endpoint

from .conftest import load_vector
from .link_rig import OnePerFrame, Rig, payload_tag, tagged_payload, wire

DATA = load_vector("arq_scenarios.json")
A = DATA["assumptions"]


def config(role: Role) -> LinkConfig:
    base = LinkConfig.ncp() if role is Role.NCP else LinkConfig.embedded_host()
    base.rx_window = A["rx_window"]
    base.ack_delay_us = A["ack_delay_us"]
    base.rto_initial_us = A["rto_initial_us"]
    base.adaptive_rto = A["rto_adaptive"]
    base.auto_credit = False
    return base


def run_receiver(sc: dict) -> None:
    name = sc["name"]
    cfg = config(Role.NCP)
    credits = list(cfg.initial_credits)
    for ep, v in sc.get("initial_credit_edge", {}).items():
        credits[int(ep)] = v
    cfg.initial_credits = tuple(credits)
    assert cfg.rx_window // 2 == A["ack_every_frames"]
    rig = Rig(cfg, 8, [(1, 4), (2, 8), (3, 4), (4, 4), (5, 2)])
    end = 0
    for inp in sc["inputs"]:
        t = inp["t"]
        end = max(end, t)
        rig.advance(t, NoSource())
        if "data" in inp:
            seq = inp["data"]
            ep = inp.get("endpoint", int(Endpoint.ZIGBEE))
            ep_seq = inp.get("ep_seq", seq)
            h = rig.data_header(seq, ep, ep_seq)
            h.retx = inp.get("retx", False)
            h.poll = inp.get("poll", False)
            rig.feed(wire(h, tagged_payload(seq)))
        elif inp.get("crc_error"):
            h = rig.data_header(9, int(Endpoint.ZIGBEE), 9)
            w = bytearray(wire(h, tagged_payload(999)))
            w[-3] ^= 0x55
            assert 0 not in w[:-1]
            rig.feed(bytes(w))
        elif "consumer_frees" in inp:
            f = inp["consumer_frees"]
            rig.link.release_credit(Endpoint(f["endpoint"]), f["frames"])
        else:
            raise AssertionError(f"{name}: unknown input {inp}")
        rig.drain_tx(NoSource())
    for e in sc["expect"]:
        end = max(end, e["t"])
    rig.advance(end + 5_000, NoSource())

    got = [s for s in rig.sent if s.header.ftype is not FrameType.DATA]
    assert len(got) == len(sc["expect"]), (name, rig.sent)
    for s, e in zip(got, sc["expect"], strict=True):
        assert s.t == e["t"], (name, s)
        assert s.header.ftype is {"ACK": FrameType.ACK, "NAK": FrameType.NAK}[e["send"]], name
        assert s.header.ack == e["ack"], name
        assert s.header.epoch == rig.epoch
        body = s.ack_body()
        assert body.sack == e["sack"], (name, s.t)
        assert body.nbad == e.get("nbad", 0), (name, s.t)
        want = [(int(k), v) for k, v in e.get("credits", {}).items()]
        assert body.credits == want, (name, s.t)
    if "delivered" in sc:
        assert [payload_tag(p) for _, p in rig.delivered] == sc["delivered"], name
    for k, v in sc.get("counters", {}).items():
        assert getattr(rig.link.counters, k) == v, (name, k)


def run_sender(sc: dict) -> None:
    name = sc["name"]
    cfg = config(Role.HOST)
    rig = Rig(cfg, A["rx_window"], [(1, 4), (2, 8), (3, 4), (4, 2), (5, 0)])
    src = OnePerFrame()
    end = 0
    for inp in sc["inputs"]:
        t = inp["t"]
        end = max(end, t)
        rig.advance(t, src)
        if "send_new" in inp:
            before = len(rig.sent)
            for s in inp["send_new"]:
                src.push(Endpoint.ZIGBEE, s)
            rig.drain_tx(src)
            new = rig.sent[before:]
            assert [s.header.seq for s in new] == inp["send_new"], name
            assert all(not s.header.retx and s.header.ftype is FrameType.DATA for s in new)
        elif "recv" in inp:
            ftype = {"ACK": FrameType.ACK, "NAK": FrameType.NAK}[inp["recv"]]
            rig.feed(rig.ack_frame(ftype, inp["ack"], inp["sack"], inp.get("nbad", 0)))
        else:
            raise AssertionError(name)
        rig.drain_tx(src)
    for e in sc["expect"]:
        end = max(end, e["t"])
    rig.advance(end + 5_000, src)
    retx = [s for s in rig.sent if s.header.retx or s.header.ftype is not FrameType.DATA]
    assert len(retx) == len(sc["expect"]), (name, rig.sent)
    for s, e in zip(retx, sc["expect"], strict=True):
        assert s.header.ftype is FrameType.DATA
        assert s.t == e["t"], name
        assert s.header.seq == e["retransmit"], name
        assert s.header.retx == ("RETX" in e["flags"])
        assert s.header.poll == ("POLL" in e["flags"])
        assert payload_tag(s.payload) == s.header.seq, "byte-identical payload"
    fin = sc["final"]
    assert rig.link.tx_base == fin["base"], name
    assert sorted(rig.link.tx_unacked()) == fin["unacked"], name
    if "rto_us" in fin:
        assert rig.link.rto_us == fin["rto_us"], name


@pytest.mark.parametrize("sc", DATA["scenarios"], ids=lambda s: s["name"])
def test_arq_scenario(sc: dict) -> None:
    {"receiver": run_receiver, "sender": run_sender}[sc["role"]](sc)


def test_all_scenarios_present() -> None:
    assert len(DATA["scenarios"]) == 8
