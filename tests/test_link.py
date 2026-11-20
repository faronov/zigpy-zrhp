"""Link conformance and property tests (spec 14.2) for the Python port."""

from __future__ import annotations

import random

import pytest

from zigpy_zrhp import frame
from zigpy_zrhp.frame import FrameType, Header, RejectBody, ResetReason
from zigpy_zrhp.link import (
    Established,
    LinkConfig,
    LinkDown,
    LinkFailed,
    LinkState,
    NoSource,
    PeerChange,
    PeerReset,
    TxFailed,
    TxFailure,
)
from zigpy_zrhp.messages import Message
from zigpy_zrhp.types import Endpoint, Kind

from .conftest import load_vector
from .link_rig import (
    Channel,
    OnePerFrame,
    Pair,
    Rig,
    decode_wire,
    payload_tag,
    tagged_payload,
    wire,
)

LINK = {v["name"]: v for v in load_vector("link_frames.json")["vectors"]}


def msg(tag: int, size: int = 0) -> bytes:
    return Message(Kind.EVENT, 0x0280, tag & 0xFFFF, bytes([tag & 0xFF]) * size).serialize()


def established_pair(**kw) -> Pair:
    p = Pair(**kw)
    p.open()
    p.run(
        50_000, stop=lambda: p.host.link.session() is not None and p.ncp.link.session() is not None
    )
    assert p.host.link.session() is not None
    assert p.ncp.link.session() is not None
    return p


def test_handshake_matches_vectors() -> None:
    p = Pair()
    p.host.link.open(0, ResetReason.HOST_OPEN)
    first = p.host.link.poll_transmit(0, NoSource())
    assert first == b"\x00" + bytes.fromhex(LINK["reset_req_host"]["wire_hex"])
    p.ncp.link.open(0, ResetReason.POWER_ON)
    p.ncp.link.poll_transmit(0, NoSource())  # its own RESET_REQ
    p.ncp.feed(0, first)
    ack = p.ncp.link.poll_transmit(0, NoSource())
    assert ack is not None
    (f,) = decode_wire(ack)
    assert f.header.ftype is FrameType.RESET_ACK
    assert frame.encode_wire(f.header, f.payload).hex() == LINK["reset_ack_ncp"]["wire_hex"]
    p.host.feed(0, ack)
    s = p.host.link.session()
    assert s is not None and s.epoch == 33
    assert s.tx_window == 16
    # The host answers the NCP's RESET_REQ / confirms; both establish.
    p.run(10_000)
    assert p.ncp.link.session().epoch == 33
    assert any(isinstance(e, Established) for e in p.host.events)


def _exchange(
    p: Pair,
    n: int,
    eps=(Endpoint.ZIGBEE, Endpoint.SYSTEM, Endpoint.BULK),
    size=40,
    until=60_000_000,
) -> None:
    rng = random.Random(1)
    for i in range(n):
        ep = eps[i % len(eps)]
        p.host.source.push(ep, msg(i, rng.randrange(size)))
        p.ncp.source.push(
            Endpoint.ZIGBEE if ep is Endpoint.SYSTEM else ep, msg(i, rng.randrange(size))
        )

    def done() -> bool:
        return _count(p.host.delivered) >= n and _count(p.ncp.delivered) >= n

    p.run(until, stop=done)


def _check_order(delivered, n) -> None:
    from zigpy_zrhp.messages import parse_batch

    per_ep: dict[Endpoint, list[int]] = {}
    for ep, payload in delivered:
        for m in parse_batch(payload):
            per_ep.setdefault(ep, []).append(m.tid)
    total = sum(len(v) for v in per_ep.values())
    assert total == n
    for tids in per_ep.values():
        assert tids == sorted(tids), "per-endpoint order"
        assert len(set(tids)) == len(tids), "exactly once"


def test_clean_exchange_and_batching() -> None:
    p = established_pair()
    _exchange(p, 300)
    _check_order(p.ncp.delivered, 300)
    _check_order(p.host.delivered, 300)
    assert p.host.link.counters.tx_retransmissions == 0
    # Batching: fewer frames than messages.
    assert p.host.link.counters.tx_frames < 300


@pytest.mark.parametrize("seed", range(6))
def test_noise_exactly_once(seed: int) -> None:
    rng = random.Random(seed)
    a = Channel(rng, ber=2e-5, drop=1e-4, zero_insert=1e-4, dup=0.01)
    b = Channel(random.Random(seed + 100), ber=2e-5, drop=1e-4, zero_insert=1e-4, dup=0.01)
    p = established_pair(a2b=a, b2a=b)
    _exchange(p, 400, size=120)
    events = p.host.events + p.ncp.events
    assert not [e for e in events if isinstance(e, (LinkDown, LinkFailed))], events
    _check_order(p.ncp.delivered, 400)
    _check_order(p.host.delivered, 400)
    assert p.host.link.counters.rx_bad_frame + p.ncp.link.counters.rx_bad_frame > 0


def test_bulk_loss_does_not_block_zigbee() -> None:
    p = established_pair()
    p.host.source.push(Endpoint.BULK, msg(1, 300))
    # Drop exactly the BULK frame on the wire.
    original = p.h2n.send

    def send(now, data, state={"dropped": False}):  # noqa: B006
        if not state["dropped"] and any(
            f.header.endpoint == Endpoint.BULK for f in decode_wire(data)
        ):
            state["dropped"] = True
            return
        original(now, data)

    p.h2n.send = send
    p.step()
    for i in range(2, 6):
        p.host.source.push(Endpoint.ZIGBEE, msg(i))
    p.run(p.now + 500_000, stop=lambda: _count(p.ncp.delivered) >= 5)
    # The ZIGBEE frame sent after the lost BULK frame is delivered first.
    assert p.ncp.delivered[0][0] is Endpoint.ZIGBEE
    assert _count(p.ncp.delivered[:1]) == 4
    assert p.ncp.delivered[-1][0] is Endpoint.BULK
    assert p.host.link.counters.tx_retransmissions == 1


def test_seq_wrap_and_window() -> None:
    p = established_pair()
    for i in range(700):
        p.host.source.push(Endpoint.ZIGBEE, msg(i, 600))  # one message per frame
    p.run(120_000_000, stop=lambda: len(p.ncp.delivered) >= 700)
    _check_order(p.ncp.delivered, 700)
    assert p.host.link.counters.tx_frames > 700  # incl. acks/keepalives


def test_peer_restart_and_resync() -> None:
    p = established_pair()
    # NCP reboots: new cookie.
    p.ncp.link.reopen(p.now, 0xDEADBEEF, ResetReason.POWER_ON)
    p.run(
        p.now + 200_000,
        stop=lambda: p.host.link.session() is not None
        and p.host.link.session().peer_cookie == 0xDEADBEEF,
    )
    resets = [e for e in p.host.events if isinstance(e, PeerReset)]
    assert resets[-1].change is PeerChange.RESTARTED
    assert p.host.link.session().epoch == frame.session_epoch(0x1A2B3C4D, 0xDEADBEEF)
    # NCP loses sync without reboot: same cookie.
    p.ncp.link.open(p.now, ResetReason.PEER_TIMEOUT)
    p.run(p.now + 500_000)
    resets = [e for e in p.host.events if isinstance(e, PeerReset)]
    assert resets[-1].change is PeerChange.RESYNC
    assert p.host.link.state is LinkState.ESTABLISHED


def test_inflight_fails_with_link_reset() -> None:
    p = established_pair()
    p.h2n.blocked = True
    p.host.source.push(Endpoint.ZIGBEE, msg(7))
    p.step()
    p.ncp.link.reopen(p.now, 0xABCDEF01, ResetReason.POWER_ON)
    p.h2n.inflight.clear()
    p.h2n.blocked = False
    p.run(p.now + 300_000)
    failed = [e for e in p.host.events if isinstance(e, TxFailed)]
    assert failed and failed[0].reason is TxFailure.LINK_RESET
    assert payload_tag(failed[0].payload) == 7


def test_retry_exhausted_resets() -> None:
    p = established_pair()
    p.h2n.blocked = True  # nothing reaches the NCP
    p.n2h.blocked = True
    p.host.source.push(Endpoint.ZIGBEE, msg(1))
    p.run(
        p.now + 20_000_000,
        stop=lambda: any(isinstance(e, (LinkFailed, LinkDown)) for e in p.host.events),
    )
    assert any(isinstance(e, (LinkFailed, LinkDown)) for e in p.host.events)
    assert p.host.link.state is LinkState.RESETTING


def test_link_down_after_silence_then_recovers() -> None:
    p = established_pair()
    p.n2h.blocked = True
    p.h2n.blocked = True
    p.run(p.now + 4_000_000, stop=lambda: any(isinstance(e, LinkDown) for e in p.host.events))
    assert any(isinstance(e, LinkDown) for e in p.host.events)
    p.n2h.blocked = False
    p.h2n.blocked = False
    p.n2h.inflight.clear()
    p.h2n.inflight.clear()
    p.run(
        p.now + 5_000_000,
        stop=lambda: p.host.link.session() is not None and p.ncp.link.session() is not None,
    )
    assert p.host.link.session() is not None


def test_stale_epoch_is_rejected() -> None:
    rig = Rig(LinkConfig.ncp(), 8, [(1, 4), (2, 8), (3, 4), (4, 4), (5, 2)])
    h = rig.data_header(0, 2, 0)
    h.epoch = (rig.epoch + 1) & 0xFF or 1
    rig.feed(wire(h, tagged_payload(1)))
    rig.drain_tx(NoSource())
    rejects = [s for s in rig.sent if s.header.ftype is FrameType.REJECT]
    assert rejects and RejectBody.parse(rejects[0].payload).reason == 6
    assert rig.link.counters.rx_epoch_mismatch == 1
    assert not rig.delivered


def test_no_credit_reject_consumes_seq() -> None:
    cfg = LinkConfig.ncp()
    rig = Rig(cfg, 8, [(1, 4), (2, 8), (3, 4), (4, 4), (5, 2)])
    # LOG credit granted by the NCP is 0: any LOG frame is NO_CREDIT.
    rig.feed(wire(rig.data_header(0, int(Endpoint.LOG), 0), tagged_payload(1)))
    rig.feed(wire(rig.data_header(1, int(Endpoint.ZIGBEE), 0), tagged_payload(2)))
    rig.drain_tx(NoSource())
    rejects = [RejectBody.parse(s.payload) for s in rig.sent if s.header.ftype is FrameType.REJECT]
    assert rejects[0].reason == 1 and rejects[0].seq == 0
    assert rig.link.rx_ack == 2
    assert [payload_tag(p) for _, p in rig.delivered] == [2]


def test_sender_reports_rejected_frame() -> None:
    rig = Rig(LinkConfig.desktop_host(), 8, [(1, 4), (2, 8), (3, 4), (4, 2), (5, 0)])
    src = OnePerFrame()
    src.push(Endpoint.ZIGBEE, 5)
    rig.drain_tx(src)
    h = Header(FrameType.REJECT, epoch=rig.epoch, ack=1)
    rig.feed(wire(h, RejectBody(0, 2, 0, 1).to_bytes()))
    failed = [e for e in rig.events if isinstance(e, TxFailed)]
    assert failed and failed[0].reason is TxFailure.REJECTED and failed[0].reject_reason == 1
    assert rig.link.counters.tx_rejected == 1


def test_simultaneous_reset_req() -> None:
    p = Pair()
    p.open()
    p.run(
        100_000, stop=lambda: p.host.link.session() is not None and p.ncp.link.session() is not None
    )
    assert p.host.link.session().epoch == p.ncp.link.session().epoch


def test_keepalive_repairs_credit() -> None:
    p = established_pair()
    # NCP grants BULK 2; send 3 bulk messages one per frame.
    for i in range(3):
        p.host.source.push(Endpoint.BULK, msg(i, 600))
    p.run(p.now + 3_000_000, stop=lambda: len(p.ncp.delivered) >= 3)
    assert len(p.ncp.delivered) == 3


def test_minimum_host_storm() -> None:
    host_cfg = LinkConfig(rx_window=4, initial_credits=(0, 4, 8, 4, 1, 0))
    p = established_pair(host_cfg=host_cfg, txw=4, rxw=4)
    for i in range(1000):
        p.ncp.source.push(Endpoint.ZIGBEE, msg(i, 42))
    p.run(
        120_000_000,
        stop=lambda: sum(1 for _ in p.host.delivered) and _count(p.host.delivered) >= 1000,
    )
    assert _count(p.host.delivered) == 1000


def _count(delivered) -> int:
    from zigpy_zrhp.messages import parse_batch

    return sum(len(parse_batch(pl)) for _, pl in delivered)
