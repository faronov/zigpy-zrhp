"""Link layer (spec 5): sessions, selective-repeat ARQ, credits, keepalive.

:class:`Link` is a sans-IO state machine and a line-by-line port of the Rust
reference ``zigbee_zrhp::link`` (``zigbee-zrhp/src/link/engine.rs``). It never
reads a clock: every call takes a monotonic time in microseconds. The caller
moves bytes between the link and the transport::

    transport RX bytes -> Link.push_rx -> Link.poll_event -> upper layer
    upper-layer queues (TxSource) <- Link.poll_transmit -> transport TX bytes
    sleep until Link.next_deadline()

The same code runs on both sides; :attr:`LinkConfig.role` selects host or NCP
behaviour.
"""

from __future__ import annotations

import dataclasses
import enum
from typing import Protocol

from . import cobs
from .frame import (
    MAX_PAYLOAD,
    AckBody,
    FrameError,
    FrameType,
    Header,
    RejectBody,
    RejectReason,
    ResetBody,
    ResetReason,
    Role,
    encode_wire,
    parse,
    raw_header,
    session_epoch,
)
from .types import BY_PRIORITY, DATA_ENDPOINTS, Endpoint

NEP = 6
#: Received-bitmap span (``ack+1 .. ack+32``) and duplicate window.
SACK_SPAN = 32
#: Idle time after which a ``0x00`` precedes the next frame (5.1).
RESYNC_IDLE_US = 100_000
#: Rate limit of REJECT ``STALE_EPOCH`` / ``UNSUPPORTED`` (5.5).
REJECT_RATE_US = 100_000
#: Anti-starvation threshold (5.10).
STARVATION_FRAMES = 8
REJECT_QUEUE = 4
CTL_QUEUE = 4


@dataclasses.dataclass
class LinkConfig:
    """Local link configuration (spec 5.8 defaults)."""

    role: Role = Role.HOST
    rx_window: int = 32
    ack_delay_us: int = 1000
    keepalive_ms: int = 500
    link_timeout_ms: int = 3000
    rto_initial_us: int = 100_000
    rto_min_us: int = 25_000
    rto_max_us: int = 1_000_000
    adaptive_rto: bool = True
    n_retx_max: int = 10
    reset_retry_ms: int = 200
    reset_retry_max_ms: int = 2000
    #: Initial credit granted to the peer, indexed by endpoint ID (0 unused).
    initial_credits: tuple[int, ...] = (0, 4, 8, 4, 4, 2)
    #: Return a delivered frame's credit when the next event is polled.
    auto_credit: bool = True

    @classmethod
    def ncp(cls) -> LinkConfig:
        return cls(role=Role.NCP, rx_window=16, initial_credits=(0, 4, 8, 4, 2, 0))

    @classmethod
    def desktop_host(cls) -> LinkConfig:
        return cls(role=Role.HOST, rx_window=32, initial_credits=(0, 4, 8, 4, 4, 2))

    @classmethod
    def embedded_host(cls) -> LinkConfig:
        return cls(role=Role.HOST, rx_window=8, initial_credits=(0, 4, 8, 4, 2, 0))


class LinkState(enum.Enum):
    UNSYNCED = "unsynced"
    RESETTING = "resetting"
    ESTABLISHED = "established"


class PeerChange(enum.Enum):
    """How a received ``RESET_*`` relates to the last known peer cookie."""

    NEW = "new"
    RESTARTED = "restarted"  # PEER_RESTARTED
    RESYNC = "resync"  # PEER_RESYNC


@dataclasses.dataclass(frozen=True)
class SessionInfo:
    epoch: int
    own_cookie: int
    peer_cookie: int
    tx_window: int
    peer_rx_mtu: int
    keepalive_ms: int
    link_timeout_ms: int


class TxFailure(enum.Enum):
    LINK_RESET = "link_reset"
    REJECTED = "rejected"


# --- Events -----------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class PeerReset:
    cookie: int
    change: PeerChange


@dataclasses.dataclass(frozen=True)
class LinkDown:
    pass


@dataclasses.dataclass(frozen=True)
class LinkFailed:
    pass


@dataclasses.dataclass(frozen=True)
class Established:
    session: SessionInfo


@dataclasses.dataclass(frozen=True)
class Data:
    endpoint: Endpoint
    payload: bytes


@dataclasses.dataclass(frozen=True)
class TxFailed:
    endpoint: Endpoint
    payload: bytes
    reason: TxFailure
    reject_reason: int | None = None


LinkEvent = PeerReset | LinkDown | LinkFailed | Established | Data | TxFailed


class TxSource(Protocol):
    """Supplies whole batched messages per endpoint (spec 5.10)."""

    def ready(self, endpoint: Endpoint) -> bool: ...

    def fill(self, endpoint: Endpoint, mtu: int) -> bytes: ...


class NoSource:
    def ready(self, endpoint: Endpoint) -> bool:
        return False

    def fill(self, endpoint: Endpoint, mtu: int) -> bytes:
        return b""


@dataclasses.dataclass
class LinkCounters:
    """Link counters (spec 5.12)."""

    tx_frames: int = 0
    tx_bytes: int = 0
    tx_retransmissions: int = 0
    tx_rto_expiries: int = 0
    tx_rejected: int = 0
    tx_blocked_credit_ms: int = 0
    tx_blocked_window_ms: int = 0
    tx_discarded_no_host: int = 0
    naks_sent: int = 0
    naks_received: int = 0
    sessions_established: int = 0
    link_down_events: int = 0
    rx_frames: int = 0
    rx_bytes: int = 0
    rx_bad_frame: int = 0
    rx_duplicate: int = 0
    rx_out_of_order: int = 0
    rx_epoch_mismatch: int = 0
    rx_not_in_session: int = 0
    rx_rejected_sent: int = 0
    rx_overflow: int = 0
    rx_stale_reset: int = 0
    peer_restarted: int = 0
    peer_resync: int = 0

    IDS = {
        "tx_frames": 0x0101,
        "tx_bytes": 0x0102,
        "tx_retransmissions": 0x0103,
        "tx_rto_expiries": 0x0104,
        "tx_rejected": 0x0105,
        "tx_blocked_credit_ms": 0x0106,
        "tx_blocked_window_ms": 0x0107,
        "tx_discarded_no_host": 0x0108,
        "naks_sent": 0x0109,
        "naks_received": 0x010A,
        "sessions_established": 0x010B,
        "link_down_events": 0x010C,
        "rx_frames": 0x0111,
        "rx_bytes": 0x0112,
        "rx_bad_frame": 0x0113,
        "rx_duplicate": 0x0114,
        "rx_out_of_order": 0x0115,
        "rx_epoch_mismatch": 0x0116,
        "rx_not_in_session": 0x0117,
        "rx_rejected_sent": 0x0118,
        "rx_overflow": 0x0119,
        "rx_stale_reset": 0x011A,
        "peer_restarted": 0x011B,
        "peer_resync": 0x011C,
    }

    def inc(self, name: str, n: int = 1) -> None:
        setattr(self, name, min(0xFFFFFFFF, getattr(self, name) + n))

    def as_dict(self) -> dict[str, int]:
        return {k: getattr(self, k) for k in self.IDS}


#: Counter ID -> name, for ``DIAG_GET_COUNTERS`` group 0x01.
COUNTER_NAMES = {v: k for k, v in LinkCounters.IDS.items()}


class _TxSlot:
    __slots__ = (
        "endpoint",
        "ep_seq",
        "failure",
        "first_tx",
        "last_tx",
        "last_tx_order",
        "needs_retx",
        "payload",
        "reject_reason",
        "retx_count",
        "retx_poll",
        "sacked",
        "seq",
        "state",
    )

    def __init__(self) -> None:
        self.state = "free"  # free | inflight | failed
        self.failure: TxFailure | None = None
        self.reject_reason: int | None = None
        self.seq = 0
        self.endpoint = 0
        self.ep_seq = 0
        self.payload = b""
        self.sacked = False
        self.needs_retx = False
        self.retx_poll = False
        self.retx_count = 0
        self.first_tx = 0
        self.last_tx = 0
        self.last_tx_order = 0


class _RxSlot:
    __slots__ = ("endpoint", "ep_seq", "order", "payload", "state")

    def __init__(self) -> None:
        self.state = "free"  # free | buffered | tombstone | ready
        self.order = 0
        self.endpoint = 0
        self.ep_seq = 0
        self.payload = b""


class _Peer:
    __slots__ = ("credits", "keepalive_ms", "link_timeout_ms", "rx_mtu", "rx_window")

    def __init__(self) -> None:
        self.rx_window = 4
        self.rx_mtu = MAX_PAYLOAD
        self.keepalive_ms = 500
        self.link_timeout_ms = 3000
        self.credits = [0] * NEP


def _endpoint(value: int) -> Endpoint | None:
    try:
        ep = Endpoint(value)
    except ValueError:
        return None
    return None if ep is Endpoint.LINK else ep


class Link:
    """The ZRHP link state machine with ``txw`` transmit and ``rxw`` receive slots."""

    def __init__(self, cfg: LinkConfig, cookie: int, *, txw: int = 32, rxw: int = 32):
        if not 1 <= txw <= 128:
            raise ValueError("txw must be 1..=128")
        if not 4 <= rxw <= 32:
            raise ValueError("rxw must be 4..=32")
        self.cfg = cfg
        self._txw = txw
        self._rxw = rxw
        self._dec = cobs.Accumulator()
        self.cookie = cookie
        self.state = LinkState.UNSYNCED
        self.peer_known: int | None = None
        self._answered: int | None = None
        self._session_peer = 0
        self.epoch = 0
        self._peer = _Peer()
        self._keepalive_us = 500_000
        self._link_timeout_us = 3_000_000
        self._tx_window = 4
        self._reset_reason = 0
        self._reset_tx: str | None = None  # "req" | "ack"
        self._reset_retry_at = 0
        self._reset_retry_ms = cfg.reset_retry_ms
        self._dup_ack_at: int | None = None
        self._rx_in_session = False
        self._any_tx = False
        self._last_tx = 0
        self._last_rx_valid = 0
        # Transmit ARQ.
        self._tx = [_TxSlot() for _ in range(txw)]
        self._next_seq = 0
        self._base = 0
        self._tx_order = 0
        self._d_max: int | None = None
        self._nbad_handled = 0
        self._tx_credit_edge = [0] * NEP
        self._next_ep_seq = [0] * NEP
        self._srtt: int | None = None
        self._rttvar = 0
        self._rto = cfg.rto_initial_us
        self._blocked_since: int | None = None
        self._blocked_by_window = False
        self._consecutive_high = 0
        self._last_served = [0] * NEP
        self._served_counter = 0
        # Receive ARQ.
        self._rx = [_RxSlot() for _ in range(rxw)]
        self._rx_ack = 0
        self._rx_bitmap = 0
        self._expected_ep_seq = [0] * NEP
        self._rx_credit_edge = [0] * NEP
        self._last_rx_ep_seq: list[int | None] = [None] * NEP
        self._credit_dirty = 0
        self._nbad = 0
        self._nbad_reported = 0
        self._frames_since_ack = 0
        self._delayed_ack_at: int | None = None
        self._ack_req: str | None = None  # None | "ack" | "nak"
        self._poll_reply = False
        self._keepalive_due = False
        self._crc_holdoff_until: int | None = None
        self._crc_nak_after_holdoff = False
        self._rejects: list[RejectBody] = []
        self._last_stale_reject: int | None = None
        self._ready_counter = 0
        # Upper-layer events.
        self._ctl: list[LinkEvent] = []
        self._established_pending = False
        self._lent: tuple[str, int] | None = None
        self.counters = LinkCounters()

    # --- Public API ----------------------------------------------------------

    def open(self, now: int, reason: ResetReason = ResetReason.HOST_OPEN) -> None:
        """(Re)start the handshake: drop ARQ state, fail unacked frames."""
        self._dec.reset()
        self._begin_reset(now, int(reason))

    def reopen(self, now: int, cookie: int, reason: ResetReason) -> None:
        self.cookie = cookie
        self.open(now, reason)

    def session(self) -> SessionInfo | None:
        if self.state is not LinkState.ESTABLISHED:
            return None
        return self._session_info()

    @property
    def rto_us(self) -> int:
        return self._rto

    @property
    def tx_base(self) -> int:
        return self._base

    @property
    def tx_next_seq(self) -> int:
        return self._next_seq

    @property
    def rx_ack(self) -> int:
        return self._rx_ack

    def tx_unacked(self) -> list[int]:
        return [s.seq for s in self._tx if s.state == "inflight" and not s.sacked]

    def tx_in_flight(self) -> list[int]:
        return [s.seq for s in self._tx if s.state == "inflight"]

    def can_send(self, endpoint: Endpoint) -> bool:
        return (
            self.state is LinkState.ESTABLISHED
            and self._admissible(endpoint)
            and self._free_tx_slot() is not None
        )

    def push_rx(self, data: bytes, now: int) -> int:
        """Feed received bytes; returns how many were consumed.

        Stops early while delivered frames wait in :meth:`poll_event`.
        """
        self._release_lent()
        i = 0
        n = len(data)
        while i < n:
            if self._has_ready():
                break
            b = data[i]
            i += 1
            res = self._dec.push(b)
            if res is None:
                continue
            if isinstance(res, cobs.BadFrame):
                self._on_bad_frame(now)
            else:
                self._on_frame(res, now)
        self.counters.inc("rx_bytes", i)
        return i

    def on_line_error(self, now: int, overrun: bool = False) -> None:
        """A UART framing/parity/overrun error: abort the frame, count ``nbad``."""
        self._dec.line_error()
        if overrun:
            self.counters.inc("rx_overflow")
        self._on_bad_frame(now)

    def note_discarded_no_host(self) -> None:
        self.counters.inc("tx_discarded_no_host")

    def poll_event(self) -> LinkEvent | None:
        self._release_lent()
        if self._ctl:
            return self._ctl.pop(0)
        failed = [(s.last_tx_order, i) for i, s in enumerate(self._tx) if s.state == "failed"]
        if failed:
            _, i = min(failed)
            self._lent = ("tx", i)
            s = self._tx[i]
            ep = _endpoint(s.endpoint) or Endpoint.LINK
            return TxFailed(ep, s.payload, s.failure or TxFailure.LINK_RESET, s.reject_reason)
        if self._established_pending:
            self._established_pending = False
            if self.state is LinkState.ESTABLISHED:
                return Established(self._session_info())
        ready = [(s.order, i) for i, s in enumerate(self._rx) if s.state == "ready"]
        if not ready:
            return None
        _, i = min(ready)
        self._lent = ("rx", i)
        s = self._rx[i]
        return Data(Endpoint(s.endpoint), s.payload)

    def release_credit(self, endpoint: Endpoint, frames: int = 1) -> None:
        """Return receive credits after the consumer freed buffers (rule R8)."""
        self._release_credit(int(endpoint), frames)

    def poll_transmit(self, now: int, src: TxSource) -> bytes | None:
        """Next wire frame due at ``now`` (timers first), or ``None``."""
        self._release_lent()
        self._handle_timers(now)
        return self._transmit(now, src)

    def next_deadline(self) -> int | None:
        if self.state is LinkState.UNSYNCED:
            return None
        if self.state is LinkState.RESETTING:
            return 0 if self._reset_tx is not None else self._reset_retry_at
        immediate = (
            self._reset_tx is not None
            or self._ack_req is not None
            or self._keepalive_due
            or bool(self._rejects)
            or any(s.state == "inflight" and s.needs_retx for s in self._tx)
        )
        if immediate:
            return 0
        t = min(
            self._last_rx_valid + self._link_timeout_us,
            self._last_tx + self._keepalive_us,
        )
        if self._delayed_ack_at is not None:
            t = min(t, self._delayed_ack_at)
        if self._crc_nak_after_holdoff and self._crc_holdoff_until is not None:
            t = min(t, self._crc_holdoff_until)
        i = self._oldest_unsacked()
        if i is not None:
            t = min(t, self._tx[i].last_tx + self._rto)
        if self._blocked_since is not None:
            t = min(t, self._blocked_since + self._keepalive_us)
        return t

    # --- Session -------------------------------------------------------------

    def _rx_window(self) -> int:
        return max(4, min(self.cfg.rx_window, self._rxw))

    def _session_info(self) -> SessionInfo:
        return SessionInfo(
            epoch=self.epoch,
            own_cookie=self.cookie,
            peer_cookie=self._session_peer,
            tx_window=self._tx_window,
            peer_rx_mtu=self._peer.rx_mtu,
            keepalive_ms=self._keepalive_us // 1000,
            link_timeout_ms=self._link_timeout_us // 1000,
        )

    def _begin_reset(self, now: int, reason: int) -> None:
        self._fail_all_inflight()
        self._clear_rx()
        self.state = LinkState.RESETTING
        self._answered = None
        self._reset_reason = reason
        self._reset_tx = "req"
        self._reset_retry_ms = self.cfg.reset_retry_ms
        self._reset_retry_at = now + self._reset_retry_ms * 1000
        self._any_tx = False

    def _push_ctl(self, ev: LinkEvent) -> None:
        self._ctl.append(ev)
        if len(self._ctl) > CTL_QUEUE:
            self._ctl.pop(0)

    def _store_peer(self, body: ResetBody) -> None:
        p = _Peer()
        for ep, value in body.credits:
            e = _endpoint(ep)
            if e is not None:
                p.credits[e] = value
        p.rx_window = max(4, min(32, body.rx_window))
        p.rx_mtu = min(body.rx_mtu, MAX_PAYLOAD)
        p.keepalive_ms = max(1, body.keepalive_ms)
        p.link_timeout_ms = body.link_timeout_ms
        self._peer = p

    def _on_reset(self, ftype: FrameType, payload: bytes, now: int) -> None:
        try:
            body = ResetBody.parse(payload)
        except ValueError:
            self.counters.inc("rx_stale_reset")
            return
        peer_role = Role.NCP if self.cfg.role is Role.HOST else Role.HOST
        if body.role != peer_role or body.cookie == 0 or body.link_version < 1:
            self.counters.inc("rx_stale_reset")
            return
        c = body.cookie
        if ftype is FrameType.RESET_REQ:
            if self.state is LinkState.RESETTING and self._answered == c:
                # Retried request: our RESET_ACK was lost.
                self._store_peer(body)
                self._reset_tx = "ack"
                return
            change = self._note_peer_cookie(c)
            self._store_peer(body)
            self._fail_all_inflight()
            self._clear_rx()
            self._push_ctl(PeerReset(c, change))
            self.state = LinkState.RESETTING
            self._answered = c
            self._reset_tx = "ack"
            self._reset_retry_ms = self.cfg.reset_retry_ms
            self._reset_retry_at = now + self._reset_retry_ms * 1000
            return
        # RESET_ACK
        if body.peer_cookie != self.cookie:
            self.counters.inc("rx_stale_reset")
            return
        if self.state is LinkState.ESTABLISHED and self._session_peer == c:
            # Duplicate RESET_ACK: the peer is still RESETTING because our
            # RESET_ACK was lost. Answer once more (rate-limited).
            if not self._rx_in_session and (
                self._dup_ack_at is None or now >= self._dup_ack_at + self.cfg.reset_retry_ms * 1000
            ):
                self._dup_ack_at = now
                self._reset_tx = "ack"
            return
        if self.peer_known != c:
            change = self._note_peer_cookie(c)
            self._fail_all_inflight()
            self._clear_rx()
            self._push_ctl(PeerReset(c, change))
        self._store_peer(body)
        if self._answered != c:
            self._answered = c
            self._reset_tx = "ack"
        else:
            self._reset_tx = None
        self._establish(c, now)

    def _note_peer_cookie(self, c: int) -> PeerChange:
        if self.peer_known is None:
            change = PeerChange.NEW
        elif self.peer_known == c:
            change = PeerChange.RESYNC
        else:
            change = PeerChange.RESTARTED
        self.counters.inc("peer_resync" if change is PeerChange.RESYNC else "peer_restarted")
        self.peer_known = c
        return change

    def _establish(self, peer_cookie: int, now: int) -> None:
        self.state = LinkState.ESTABLISHED
        self._session_peer = peer_cookie
        if self.cfg.role is Role.HOST:
            h, n = self.cookie, peer_cookie
        else:
            h, n = peer_cookie, self.cookie
        self.epoch = session_epoch(h, n)
        self._next_seq = 0
        self._base = 0
        self._d_max = None
        self._nbad_handled = 0
        self._tx_credit_edge = list(self._peer.credits)
        self._next_ep_seq = [0] * NEP
        self._srtt = None
        self._rttvar = 0
        self._rto = self.cfg.rto_initial_us
        self._blocked_since = None
        self._consecutive_high = 0
        self._rx_ack = 0
        self._rx_bitmap = 0
        self._expected_ep_seq = [0] * NEP
        credits = list(self.cfg.initial_credits) + [0] * NEP
        self._rx_credit_edge = credits[:NEP]
        self._rx_credit_edge[0] = 0
        self._last_rx_ep_seq = [None] * NEP
        self._credit_dirty = 0
        self._nbad = 0
        self._nbad_reported = 0
        self._frames_since_ack = 0
        self._delayed_ack_at = None
        self._ack_req = None
        self._poll_reply = False
        self._keepalive_due = False
        self._crc_holdoff_until = None
        self._crc_nak_after_holdoff = False
        self._rejects = []
        ka = max(1, min(self.cfg.keepalive_ms, self._peer.keepalive_ms))
        self._keepalive_us = ka * 1000
        lt = max(self.cfg.link_timeout_ms, self._peer.link_timeout_ms, 3 * ka)
        self._link_timeout_us = lt * 1000
        self._tx_window = min(self._peer.rx_window, min(self._txw, 32))
        self._last_rx_valid = now
        self._last_tx = now
        self._rx_in_session = False
        self._dup_ack_at = None
        self._established_pending = True
        self.counters.inc("sessions_established")

    def _fail_all_inflight(self) -> None:
        for s in self._tx:
            if s.state == "inflight":
                s.state = "failed"
                s.failure = TxFailure.LINK_RESET
                s.reject_reason = None
                s.needs_retx = False

    def _clear_rx(self) -> None:
        # Ready frames were accepted (and possibly acknowledged); they are
        # still delivered. Buffered frames were at most sacked.
        for s in self._rx:
            if s.state in ("buffered", "tombstone"):
                s.state = "free"
        self._rx_bitmap = 0

    def _link_failed(self, now: int, reason: ResetReason) -> None:
        self._push_ctl(LinkFailed())
        self._begin_reset(now, int(reason))

    # --- Receive -------------------------------------------------------------

    def _has_ready(self) -> bool:
        return any(s.state == "ready" for s in self._rx)

    def _on_bad_frame(self, now: int) -> None:
        self.counters.inc("rx_bad_frame")
        self._nbad = min(255, self._nbad + 1)
        if self.state is not LinkState.ESTABLISHED:
            return
        t = self._crc_holdoff_until
        if t is not None and now < t:
            self._crc_nak_after_holdoff = True
        else:
            self._ack_req = "nak"
            self._crc_holdoff_until = now + self.cfg.ack_delay_us
            self._crc_nak_after_holdoff = False

    def _queue_reject(self, body: RejectBody) -> None:
        if len(self._rejects) < REJECT_QUEUE:
            self._rejects.append(body)
            self.counters.inc("rx_rejected_sent")

    def _on_frame(self, decoded: bytes, now: int) -> None:
        try:
            f = parse(decoded)
        except FrameError as e:
            if e.is_noise:
                self._on_bad_frame(now)
                return
            # Valid CRC: a peer bug or version mismatch, not noise.
            self._nbad = 0
            if self.state is LinkState.ESTABLISHED and self._stale_reject_allowed(now):
                h = raw_header(decoded) or bytes(8)
                self._queue_reject(RejectBody(h[3], h[2], h[5], int(RejectReason.UNSUPPORTED)))
            return
        self.counters.inc("rx_frames")
        self._nbad = 0
        h = f.header
        if h.ftype in (FrameType.RESET_REQ, FrameType.RESET_ACK):
            self._on_reset(h.ftype, f.payload, now)
            return
        if self.state is not LinkState.ESTABLISHED:
            self.counters.inc("rx_not_in_session")
            return
        if h.epoch != self.epoch:
            self.counters.inc("rx_epoch_mismatch")
            if h.ftype is FrameType.DATA and self._stale_reject_allowed(now):
                self._queue_reject(
                    RejectBody(h.seq, h.endpoint, h.ep_seq, int(RejectReason.STALE_EPOCH))
                )
            return
        self._last_rx_valid = now
        self._rx_in_session = True
        if h.ftype is FrameType.DATA:
            self._process_ack(h.ack, None, now)
            self._on_data(h, f.payload, now)
        elif h.ftype in (FrameType.ACK, FrameType.NAK):
            try:
                body = AckBody.parse(f.payload)
            except ValueError:
                return
            for ep, value in body.credits:
                e = _endpoint(ep)
                if e is not None:
                    self._tx_credit_edge[e] = value
            self._process_ack(h.ack, body.sack, now)
            if h.ftype is FrameType.NAK:
                self.counters.inc("naks_received")
                self._process_nbad(body.nbad)
        elif h.ftype is FrameType.REJECT:
            try:
                self._on_reject(RejectBody.parse(f.payload), now)
            except ValueError:
                pass
            if self.state is LinkState.ESTABLISHED:
                self._process_ack(h.ack, None, now)
        if h.poll and self.state is LinkState.ESTABLISHED:
            self._poll_reply = True
            if self._ack_req is None:
                self._ack_req = "ack"

    def _stale_reject_allowed(self, now: int) -> bool:
        if self._last_stale_reject is None or now >= self._last_stale_reject + REJECT_RATE_US:
            self._last_stale_reject = now
            return True
        return False

    def _request_ack(self, kind: str) -> None:
        if kind == "nak" or self._ack_req is None:
            self._ack_req = kind

    def _free_rx_slot(self) -> int | None:
        for i, s in enumerate(self._rx):
            if s.state == "free":
                return i
        return None

    def _on_data(self, h: Header, payload: bytes, now: int) -> None:
        d = (h.seq - self._rx_ack) & 0xFF
        rx_window = self._rx_window()
        already = 0 < d <= SACK_SPAN and bool(self._rx_bitmap & (1 << (d - 1)))
        if d >= 256 - SACK_SPAN or already:
            # R4 duplicate.
            self.counters.inc("rx_duplicate")
            self._request_ack("ack")
            return
        if d >= rx_window:
            # R5 outside the window.
            self._queue_reject(
                RejectBody(h.seq, h.endpoint, h.ep_seq, int(RejectReason.WINDOW_VIOLATION))
            )
            return
        ep = _endpoint(h.endpoint)
        reject: RejectReason | None
        if ep is None:
            reject = RejectReason.UNKNOWN_ENDPOINT
        elif len(payload) > MAX_PAYLOAD:
            reject = RejectReason.TOO_LONG
        else:
            avail = (self._rx_credit_edge[ep] - h.ep_seq) & 0xFF
            reject = None if 1 <= avail <= 128 else RejectReason.NO_CREDIT
        slot: int | None = None
        if ep is not None:
            slot = self._free_rx_slot()
            if slot is None:
                # Drop unrecorded so the peer retransmits.
                self.counters.inc("rx_overflow")
                return
        hole_filled = d == 0 and self._rx_bitmap != 0
        if d == 0:
            self._rx_ack = (self._rx_ack + 1) & 0xFF
            while True:
                b0 = self._rx_bitmap & 1
                self._rx_bitmap >>= 1
                if not b0:
                    break
                self._rx_ack = (self._rx_ack + 1) & 0xFF
        else:
            self._rx_bitmap |= 1 << (d - 1)
        if ep is not None and slot is not None:
            s = self._rx[slot]
            s.endpoint = int(ep)
            s.ep_seq = h.ep_seq
            if reject is not None:
                s.state = "tombstone"
                s.payload = b""
            else:
                s.state = "buffered"
                s.payload = bytes(payload)
                self._last_rx_ep_seq[ep] = h.ep_seq
            self._deliver_ready(int(ep))
        if reject is not None:
            self._queue_reject(RejectBody(h.seq, h.endpoint, h.ep_seq, int(reject)))
        if d == 0:
            if hole_filled:
                self._request_ack("ack")  # R3
            else:
                # R1.
                self._frames_since_ack = min(255, self._frames_since_ack + 1)
                if self._delayed_ack_at is None:
                    self._delayed_ack_at = now + self.cfg.ack_delay_us
                if self._frames_since_ack >= max(1, rx_window // 2):
                    self._request_ack("ack")
        else:
            # R2.
            self.counters.inc("rx_out_of_order")
            self._request_ack("nak")

    def _deliver_ready(self, e: int) -> None:
        while True:
            exp = self._expected_ep_seq[e]
            idx = None
            for i, s in enumerate(self._rx):
                if s.state in ("buffered", "tombstone") and s.endpoint == e and s.ep_seq == exp:
                    idx = i
                    break
            if idx is None:
                return
            self._expected_ep_seq[e] = (exp + 1) & 0xFF
            s = self._rx[idx]
            if s.state == "tombstone":
                # A rejected frame consumed its ep_seq without holding a buffer.
                s.state = "free"
                self._rx_credit_edge[e] = (self._rx_credit_edge[e] + 1) & 0xFF
                self._credit_dirty |= 1 << e
            else:
                s.state = "ready"
                s.order = self._ready_counter
                self._ready_counter += 1

    def _release_credit(self, e: int, frames: int) -> None:
        if e <= 0 or e >= NEP or frames == 0 or self.state is not LinkState.ESTABLISHED:
            return
        old = self._rx_credit_edge[e]
        self._rx_credit_edge[e] = (old + frames) & 0xFF
        self._credit_dirty |= 1 << e
        if self._last_rx_ep_seq[e] == ((old - 1) & 0xFF):
            # R8: the peer is blocked on this endpoint.
            self._request_ack("ack")

    # --- Transmit-side acknowledgement processing ----------------------------

    def _process_ack(self, ack: int, sack: int | None, now: int) -> None:
        inflight = (self._next_seq - self._base) & 0xFF
        adv = (ack - self._base) & 0xFF
        if adv > inflight:
            return  # stale or bogus
        d: int | None = None
        sample: int | None = None
        base = self._base
        for s in self._tx:
            if s.state != "inflight":
                continue
            off = (s.seq - base) & 0xFF
            if off < adv:
                if not s.sacked:
                    d = s.last_tx_order if d is None else max(d, s.last_tx_order)
                    if s.retx_count == 0:
                        sample = max(0, now - s.first_tx)
                s.state = "free"
                s.needs_retx = False
            elif sack is not None:
                i = (s.seq - ack - 1) & 0xFF
                if i < SACK_SPAN and sack & (1 << i) and not s.sacked:
                    s.sacked = True
                    s.needs_retx = False
                    d = s.last_tx_order if d is None else max(d, s.last_tx_order)
                    if s.retx_count == 0:
                        sample = max(0, now - s.first_tx)
        self._base = ack
        if sample is not None and self.cfg.adaptive_rto:
            self._rtt_sample(sample)
        if d is not None:
            # S1: FIFO loss inference.
            for s in self._tx:
                if s.state == "inflight" and not s.sacked and s.last_tx_order < d:
                    s.needs_retx = True
            if self._d_max is None or d > self._d_max:
                self._d_max = d
                self._nbad_handled = 0
            self._blocked_since = None

    def _process_nbad(self, k: int) -> None:
        # S2.
        if k <= self._nbad_handled:
            return
        d_max = self._d_max
        lst = [
            s
            for s in self._tx
            if s.state == "inflight" and not s.sacked and (d_max is None or s.last_tx_order > d_max)
        ]
        lst.sort(key=lambda s: s.last_tx_order)
        for s in lst[self._nbad_handled : min(k, len(lst))]:
            s.needs_retx = True
        self._nbad_handled = k

    def _on_reject(self, body: RejectBody, now: int) -> None:
        reason = body.reason
        if reason in (
            RejectReason.NO_CREDIT,
            RejectReason.TOO_LONG,
            RejectReason.UNKNOWN_ENDPOINT,
        ):
            for s in self._tx:
                if s.state == "inflight" and s.seq == body.seq:
                    s.state = "failed"
                    s.failure = TxFailure.REJECTED
                    s.reject_reason = reason
                    s.needs_retx = False
                    self.counters.inc("tx_rejected")
                    break
        elif reason == RejectReason.WINDOW_VIOLATION:
            for s in self._tx:
                if s.state == "inflight" and s.seq == body.seq:
                    s.state = "failed"
                    s.failure = TxFailure.REJECTED
                    s.reject_reason = reason
                    self.counters.inc("tx_rejected")
                    break
            self._link_failed(now, ResetReason.PROTOCOL_ERROR)
        # STALE_EPOCH / NOT_IN_SESSION / UNSUPPORTED change no ARQ state.

    def _rtt_sample(self, r: int) -> None:
        # RFC 6298.
        if self._srtt is None:
            self._srtt = r
            self._rttvar = r // 2
        else:
            diff = abs(self._srtt - r)
            self._rttvar = (3 * self._rttvar + diff) // 4
            self._srtt = (7 * self._srtt + r) // 8
        rto = self._srtt + 4 * self._rttvar
        self._rto = max(self.cfg.rto_min_us, min(self.cfg.rto_max_us, rto))

    # --- Timers --------------------------------------------------------------

    def _oldest_unsacked(self) -> int | None:
        best = None
        for i, s in enumerate(self._tx):
            if s.state == "inflight" and not s.sacked:
                if best is None or s.last_tx_order < self._tx[best].last_tx_order:
                    best = i
        return best

    def _handle_timers(self, now: int) -> None:
        if self.state is LinkState.UNSYNCED:
            return
        if self.state is LinkState.RESETTING:
            if now >= self._reset_retry_at:
                self._reset_tx = "ack" if self._answered is not None else "req"
                self._any_tx = False
                self._reset_retry_ms = min(self._reset_retry_ms * 2, self.cfg.reset_retry_max_ms)
                self._reset_retry_at = now + self._reset_retry_ms * 1000
            return
        if now >= self._last_rx_valid + self._link_timeout_us:
            self.counters.inc("link_down_events")
            self._push_ctl(LinkDown())
            self._begin_reset(now, int(ResetReason.PEER_TIMEOUT))
            return
        if self._delayed_ack_at is not None and now >= self._delayed_ack_at:
            self._request_ack("ack")
        if self._crc_holdoff_until is not None and now >= self._crc_holdoff_until:
            self._crc_holdoff_until = None
            if self._crc_nak_after_holdoff and self._nbad != self._nbad_reported:
                self._ack_req = "nak"
                self._crc_holdoff_until = now + self.cfg.ack_delay_us
            self._crc_nak_after_holdoff = False
        # S3: RTO on the oldest unacked, unsacked frame.
        i = self._oldest_unsacked()
        if i is not None:
            s = self._tx[i]
            if not s.needs_retx and now >= s.last_tx + self._rto:
                self.counters.inc("tx_rto_expiries")
                s.needs_retx = True
                s.retx_poll = True
                self._rto = min(self._rto * 2, self.cfg.rto_max_us)
        if now >= self._last_tx + self._keepalive_us:
            self._keepalive_due = True
        # S5: blocked sender.
        b = self._blocked_since
        if b is not None and now >= b + self._keepalive_us:
            ms = (now - b) // 1000
            self.counters.inc(
                "tx_blocked_window_ms" if self._blocked_by_window else "tx_blocked_credit_ms",
                ms,
            )
            self._keepalive_due = True
            self._blocked_since = now

    # --- Transmit ------------------------------------------------------------

    def _lead_zero(self, now: int) -> bool:
        lead = not self._any_tx or now >= self._last_tx + RESYNC_IDLE_US
        self._any_tx = True
        return lead

    def _sent(self, now: int, n: int) -> None:
        self._last_tx = now
        self.counters.inc("tx_frames")
        self.counters.inc("tx_bytes", n)

    def _transmit(self, now: int, src: TxSource) -> bytes | None:
        if self._reset_tx is not None:
            kind = self._reset_tx
            self._reset_tx = None
            return self._send_reset(kind, now)
        if self.state is not LinkState.ESTABLISHED:
            return None
        if self._rejects:
            body = self._rejects.pop(0)
            h = Header(FrameType.REJECT, epoch=self.epoch, ack=self._rx_ack)
            w = encode_wire(h, body.to_bytes(), self._lead_zero(now))
            self._sent(now, len(w))
            return w
        if self._ack_req is not None:
            return self._send_ack(self._ack_req, False, False, now)
        w = self._send_retransmission(now)
        if w is not None:
            return w
        w = self._send_new(now, src)
        if w is not None:
            return w
        if self._keepalive_due:
            self._keepalive_due = False
            return self._send_ack("ack", True, True, now)
        return None

    def _send_reset(self, kind: str, now: int) -> bytes:
        if kind == "req":
            ftype = FrameType.RESET_REQ
            peer_cookie = self.peer_known or 0
        else:
            ftype = FrameType.RESET_ACK
            peer_cookie = self._answered if self._answered is not None else (self.peer_known or 0)
        credits = list(self.cfg.initial_credits) + [0] * NEP
        body = ResetBody(
            cookie=self.cookie,
            peer_cookie=peer_cookie,
            role=int(self.cfg.role),
            rx_window=self._rx_window(),
            reason=self._reset_reason,
            rx_mtu=MAX_PAYLOAD,
            ack_delay_us=self.cfg.ack_delay_us,
            keepalive_ms=self.cfg.keepalive_ms,
            link_timeout_ms=self.cfg.link_timeout_ms,
            credits=[(int(ep), credits[ep]) for ep in DATA_ENDPOINTS],
        )
        w = encode_wire(Header(ftype), body.to_bytes(), self._lead_zero(now))
        self._sent(now, len(w))
        return w

    def _send_ack(self, kind: str, poll: bool, all_credits: bool, now: int) -> bytes:
        credits = [
            (int(ep), self._rx_credit_edge[ep])
            for ep in DATA_ENDPOINTS
            if all_credits or self._credit_dirty & (1 << ep)
        ]
        self._credit_dirty = 0
        body = AckBody(self._rx_bitmap, self._nbad, credits)
        h = Header(
            FrameType.NAK if kind == "nak" else FrameType.ACK,
            epoch=self.epoch,
            ack=self._rx_ack,
            poll=poll,
        )
        w = encode_wire(h, body.to_bytes(), self._lead_zero(now))
        if kind == "nak":
            self.counters.inc("naks_sent")
        self._nbad_reported = self._nbad
        self._frames_since_ack = 0
        self._delayed_ack_at = None
        self._ack_req = None
        self._poll_reply = False
        self._sent(now, len(w))
        return w

    def _send_retransmission(self, now: int) -> bytes | None:
        cands = [
            (s.last_tx_order, i)
            for i, s in enumerate(self._tx)
            if s.state == "inflight" and s.needs_retx
        ]
        if not cands:
            return None
        _, i = min(cands)
        s = self._tx[i]
        if s.retx_count >= self.cfg.n_retx_max:
            # S4.
            self._link_failed(now, ResetReason.RETRY_EXHAUSTED)
            kind = self._reset_tx
            self._reset_tx = None
            return self._send_reset(kind, now) if kind else None
        self._tx_order += 1
        lead = self._lead_zero(now)
        s.needs_retx = False
        s.retx_count += 1
        s.last_tx = now
        s.last_tx_order = self._tx_order
        poll = s.retx_poll
        s.retx_poll = False
        h = Header(
            FrameType.DATA,
            epoch=self.epoch,
            endpoint=s.endpoint,
            seq=s.seq,
            ack=self._rx_ack,
            ep_seq=s.ep_seq,
            retx=True,
            poll=poll,
        )
        w = encode_wire(h, s.payload, lead)
        self.counters.inc("tx_retransmissions")
        self._sent(now, len(w))
        return w

    def _free_tx_slot(self) -> int | None:
        for i, s in enumerate(self._tx):
            if s.state == "free":
                return i
        return None

    def _window_open(self) -> bool:
        return ((self._next_seq - self._base) & 0xFF) < self._tx_window

    def _credit_ok(self, e: int) -> bool:
        return 1 <= ((self._tx_credit_edge[e] - self._next_ep_seq[e]) & 0xFF) <= 128

    def _bulk_quota_ok(self) -> bool:
        used = sum(
            1
            for s in self._tx
            if s.state == "inflight" and s.endpoint in (Endpoint.BULK, Endpoint.LOG)
        )
        return used < max(1, self._tx_window // 2)

    def _admissible(self, ep: Endpoint) -> bool:
        return (
            ep is not Endpoint.LINK
            and self._window_open()
            and self._credit_ok(int(ep))
            and (not ep.is_bulk_class or self._bulk_quota_ok())
        )

    def _send_new(self, now: int, src: TxSource) -> bytes | None:
        if not any(src.ready(e) for e in BY_PRIORITY):
            self._blocked_since = None
            return None
        slot = self._free_tx_slot()
        cands: list[Endpoint] = []
        if slot is not None:
            cands = [e for e in BY_PRIORITY if src.ready(e) and self._admissible(e)]
        if not cands:
            if self._blocked_since is None:
                self._blocked_since = now
                self._blocked_by_window = not self._window_open() or slot is None
            return None
        chosen = cands[0]
        if len(cands) > 1:
            if self._consecutive_high >= STARVATION_FRAMES:
                # Anti-starvation: the longest-waiting lower-priority endpoint.
                chosen = min(cands[1:], key=lambda e: self._last_served[e])
                self._consecutive_high = 0
            else:
                self._consecutive_high += 1
        else:
            self._consecutive_high = 0
        assert slot is not None
        e = int(chosen)
        mtu = min(self._peer.rx_mtu, MAX_PAYLOAD)
        payload = src.fill(chosen, mtu)
        if not payload or len(payload) > mtu:
            return None
        self._blocked_since = None
        self._served_counter += 1
        self._last_served[e] = self._served_counter
        self._tx_order += 1
        seq = self._next_seq
        ep_seq = self._next_ep_seq[e]
        self._next_seq = (seq + 1) & 0xFF
        self._next_ep_seq[e] = (ep_seq + 1) & 0xFF
        lead = self._lead_zero(now)
        s = self._tx[slot]
        s.state = "inflight"
        s.failure = None
        s.reject_reason = None
        s.seq = seq
        s.endpoint = e
        s.ep_seq = ep_seq
        s.payload = bytes(payload)
        s.sacked = False
        s.needs_retx = False
        s.retx_poll = False
        s.retx_count = 0
        s.first_tx = now
        s.last_tx = now
        s.last_tx_order = self._tx_order
        h = Header(
            FrameType.DATA,
            epoch=self.epoch,
            endpoint=e,
            seq=seq,
            ack=self._rx_ack,
            ep_seq=ep_seq,
        )
        w = encode_wire(h, s.payload, lead)
        self._sent(now, len(w))
        return w

    # --- Events --------------------------------------------------------------

    def _release_lent(self) -> None:
        lent = self._lent
        if lent is None:
            return
        self._lent = None
        kind, i = lent
        if kind == "rx":
            s = self._rx[i]
            e = s.endpoint
            s.state = "free"
            s.payload = b""
            if self.cfg.auto_credit:
                self._release_credit(e, 1)
        else:
            self._tx[i].state = "free"
            self._tx[i].payload = b""
