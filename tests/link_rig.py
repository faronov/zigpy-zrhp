"""Link test harness: a scripted peer and two-link simulations on a virtual clock.

Mirrors ``zigbee-zrhp/tests/common/harness.rs``.
"""

from __future__ import annotations

import collections
from collections.abc import Callable
import dataclasses
import random
import struct

from zigpy_zrhp import cobs, frame
from zigpy_zrhp.frame import AckBody, FrameType, Header, ResetBody, ResetReason, Role
from zigpy_zrhp.link import Data, Link, LinkConfig, NoSource
from zigpy_zrhp.messages import Message
from zigpy_zrhp.types import Endpoint, Kind

PEER_COOKIE = 0x1A2B3C4D
OWN_COOKIE = 0xC0FFEE01


@dataclasses.dataclass
class Sent:
    t: int
    header: Header
    payload: bytes

    def ack_body(self) -> AckBody:
        return AckBody.parse(self.payload)


def decode_wire(data: bytes) -> list[frame.Frame]:
    acc = cobs.Accumulator()
    out = []
    for b in data:
        r = acc.push(b)
        if isinstance(r, bytes):
            out.append(frame.parse(r))
    return out


def wire(h: Header, payload: bytes) -> bytes:
    return frame.encode_wire(h, payload)


def reset_payload(cookie, peer_cookie, role, rx_window, credits) -> bytes:
    return ResetBody(
        cookie=cookie,
        peer_cookie=peer_cookie,
        role=int(role),
        rx_window=rx_window,
        reason=4,
        credits=list(credits),
    ).to_bytes()


def tagged_payload(tag: int) -> bytes:
    return Message(Kind.REQUEST, 0x0201, tag, b"").serialize()


def payload_tag(p: bytes) -> int:
    return struct.unpack_from("<H", p, 3)[0]


class OnePerFrame:
    def __init__(self) -> None:
        self.queue: collections.deque[tuple[Endpoint, int]] = collections.deque()

    def push(self, ep: Endpoint, tag: int) -> None:
        self.queue.append((ep, tag))

    def ready(self, endpoint: Endpoint) -> bool:
        return any(e == endpoint for e, _ in self.queue)

    def fill(self, endpoint: Endpoint, mtu: int) -> bytes:
        for i, (e, tag) in enumerate(self.queue):
            if e == endpoint:
                del self.queue[i]
                return tagged_payload(tag)
        return b""


class Rig:
    """One link against a scripted peer."""

    def __init__(self, cfg: LinkConfig, peer_window: int, peer_credits, *, txw=8, rxw=8):
        self.peer_role = Role.NCP if cfg.role is Role.HOST else Role.HOST
        self.link = Link(cfg, OWN_COOKIE, txw=txw, rxw=rxw)
        self.now = 0
        self.sent: list[Sent] = []
        self.delivered: list[tuple[Endpoint, bytes]] = []
        self.events: list[object] = []
        self.link.open(0, ResetReason.POWER_ON)
        self.drain_tx(NoSource())
        p = reset_payload(PEER_COOKIE, OWN_COOKIE, self.peer_role, peer_window, peer_credits)
        self.feed(wire(Header(FrameType.RESET_ACK), p))
        self.drain_tx(NoSource())
        s = self.link.session()
        assert s is not None
        self.epoch = s.epoch
        h, n = (OWN_COOKIE, PEER_COOKIE) if cfg.role is Role.HOST else (PEER_COOKIE, OWN_COOKIE)
        assert s.epoch == frame.session_epoch(h, n)
        self.sent.clear()
        self.events.clear()

    def feed(self, data: bytes) -> None:
        off = 0
        while off < len(data):
            off += self.link.push_rx(data[off:], self.now)
            self.drain_events()

    def drain_events(self) -> None:
        while (ev := self.link.poll_event()) is not None:
            if isinstance(ev, Data):
                self.delivered.append((ev.endpoint, ev.payload))
            else:
                self.events.append(ev)

    def drain_tx(self, src) -> int:
        count = 0
        while (w := self.link.poll_transmit(self.now, src)) is not None:
            for f in decode_wire(w):
                self.sent.append(Sent(self.now, f.header, f.payload))
            count += 1
            assert count < 10_000
        self.drain_events()
        return count

    def advance(self, to: int, src) -> None:
        guard = 0
        while (d := self.link.next_deadline()) is not None and d <= to:
            self.now = max(self.now, d)
            if self.drain_tx(src) == 0 and self.link.next_deadline() == d:
                break
            guard += 1
            assert guard < 10_000
        self.now = max(self.now, to)
        self.drain_tx(src)

    def data_header(self, seq: int, endpoint: int, ep_seq: int) -> Header:
        return Header(FrameType.DATA, epoch=self.epoch, endpoint=endpoint, seq=seq, ep_seq=ep_seq)

    def ack_frame(self, ftype, ack, sack, nbad=0, credits=()) -> bytes:
        h = Header(ftype, epoch=self.epoch, ack=ack)
        return wire(h, AckBody(sack, nbad, list(credits)).to_bytes())


class QueueSource:
    """A TX source of whole messages per endpoint with opportunistic batching."""

    def __init__(self) -> None:
        self.queues: dict[Endpoint, collections.deque[bytes]] = collections.defaultdict(
            collections.deque
        )

    def push(self, ep: Endpoint, message: bytes) -> None:
        self.queues[ep].append(message)

    def ready(self, endpoint: Endpoint) -> bool:
        return bool(self.queues.get(endpoint))

    def fill(self, endpoint: Endpoint, mtu: int) -> bytes:
        q = self.queues[endpoint]
        out = bytearray()
        while q and len(out) + len(q[0]) <= mtu:
            out += q.popleft()
        return bytes(out)


class Channel:
    """A unidirectional byte pipe with optional fault injection."""

    def __init__(
        self,
        rng: random.Random | None = None,
        *,
        ber=0.0,
        drop=0.0,
        zero_insert=0.0,
        dup=0.0,
        latency_us=200,
    ) -> None:
        self.rng = rng or random.Random(0)
        self.ber = ber
        self.drop = drop
        self.zero_insert = zero_insert
        self.dup = dup
        self.latency_us = latency_us
        self.inflight: collections.deque[tuple[int, bytes]] = collections.deque()
        self.blocked = False

    def send(self, now: int, data: bytes) -> None:
        r = self.rng
        out = bytearray()
        for b in data:
            if self.drop and r.random() < self.drop:
                continue
            if self.ber:
                for bit in range(8):
                    if r.random() < self.ber:
                        b ^= 1 << bit
            out.append(b)
            if self.zero_insert and r.random() < self.zero_insert:
                out.append(0)
        chunk = bytes(out)
        self.inflight.append((now + self.latency_us, chunk))
        if self.dup and r.random() < self.dup:
            self.inflight.append((now + self.latency_us, chunk))

    def due(self, now: int) -> bytes:
        if self.blocked:
            return b""
        out = bytearray()
        while self.inflight and self.inflight[0][0] <= now:
            out += self.inflight.popleft()[1]
        return bytes(out)

    def next_time(self) -> int | None:
        if self.blocked or not self.inflight:
            return None
        return self.inflight[0][0]


class Side:
    def __init__(self, link: Link, source) -> None:
        self.link = link
        self.source = source
        self.delivered: list[tuple[Endpoint, bytes]] = []
        self.events: list[object] = []
        self._pending = b""

    def feed(self, now: int, data: bytes) -> None:
        data = self._pending + data
        off = 0
        while off < len(data):
            n = self.link.push_rx(data[off:], now)
            off += n
            self.drain_events()
        self._pending = b""

    def drain_events(self) -> None:
        while (ev := self.link.poll_event()) is not None:
            if isinstance(ev, Data):
                self.delivered.append((ev.endpoint, ev.payload))
            else:
                self.events.append(ev)


class Pair:
    """Host and NCP links connected by two channels on a virtual clock."""

    def __init__(
        self,
        host_cfg=None,
        ncp_cfg=None,
        *,
        a2b=None,
        b2a=None,
        host_cookie=PEER_COOKIE,
        ncp_cookie=OWN_COOKIE,
        txw=32,
        rxw=32,
    ) -> None:
        self.now = 0
        self.host = Side(
            Link(host_cfg or LinkConfig.desktop_host(), host_cookie, txw=txw, rxw=rxw),
            QueueSource(),
        )
        self.ncp = Side(
            Link(ncp_cfg or LinkConfig.ncp(), ncp_cookie, txw=16, rxw=16), QueueSource()
        )
        self.h2n = a2b or Channel()
        self.n2h = b2a or Channel()

    def open(self) -> None:
        self.host.link.open(self.now, ResetReason.HOST_OPEN)
        self.ncp.link.open(self.now, ResetReason.POWER_ON)

    def _pump_tx(self, side: Side, ch: Channel) -> None:
        while (w := side.link.poll_transmit(self.now, side.source)) is not None:
            ch.send(self.now, w)
        side.drain_events()

    def step(self) -> None:
        self._pump_tx(self.host, self.h2n)
        self._pump_tx(self.ncp, self.n2h)
        data = self.h2n.due(self.now)
        if data:
            self.ncp.feed(self.now, data)
        data = self.n2h.due(self.now)
        if data:
            self.host.feed(self.now, data)
        self._pump_tx(self.host, self.h2n)
        self._pump_tx(self.ncp, self.n2h)

    def run(self, until: int, stop: Callable[[], bool] | None = None, max_step=1000) -> None:
        guard = 0
        while self.now < until:
            self.step()
            if stop is not None and stop():
                return
            cands = [
                t
                for t in (
                    self.host.link.next_deadline(),
                    self.ncp.link.next_deadline(),
                    self.h2n.next_time(),
                    self.n2h.next_time(),
                )
                if t is not None
            ]
            nxt = min(cands) if cands else until
            nxt = max(self.now + 1, min(nxt, self.now + max_step, until))
            self.now = nxt
            guard += 1
            assert guard < 2_000_000
        self.step()
