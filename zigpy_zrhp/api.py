"""Request/response, events and the session lifecycle on top of the link.

:class:`ZrhpApi` owns the port and the :class:`~zigpy_zrhp.transport.LinkDriver`.
It allocates TIDs, matches responses, retries requests after a link resync
with the ``RETRY`` flag (spec 6.5), answers NCP-originated requests through a
handler, and runs the session handshake: after every ``ESTABLISHED`` it waits
for ``EVT_NCP_READY`` and sends ``SYS_NEGOTIATE`` before releasing requests.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
import contextlib
import dataclasses
import logging
import secrets
from typing import Any

from . import __version__, messages as m
from .codec import CodecError, Struct
from .frame import ResetReason
from .link import (
    Data,
    Established,
    LinkConfig,
    LinkDown,
    LinkEvent,
    LinkFailed,
    PeerChange,
    PeerReset,
    TxFailed,
    TxFailure,
)
from .transport import ByteTransport, LinkDriver
from .types import Capacity, Endpoint, HostCaps, Kind, NcpCaps, Status

LOGGER = logging.getLogger(__name__)

MAJOR = 1
DEFAULT_TIMEOUT = 5.0
HOST_CAPS = (
    HostCaps.HOST_TABLES | HostCaps.FC_CHECKPOINTS | HostCaps.RETRY_CACHE | HostCaps.GP_SHADOW
)


#: Response bytes the host lets the NCP owe per endpoint. The NCP queues its
#: responses in a 1 536-byte buffer per endpoint (1 024 on compact parts) and
#: drops what does not fit, so the host bounds what it has in flight.
RESPONSE_BUDGET = 1024
_DEFAULT_RESPONSE = 48


def _expected_response(msg_id: int, payload: bytes) -> int:
    """A generous estimate of the response size of a request (header included)."""
    if msg_id == m.Id.SYS_ECHO:
        return 8 + len(payload)
    if msg_id == m.Id.BKP_EXPORT_READ and len(payload) >= 4:
        return 10 + int.from_bytes(payload[2:4], "little")
    if msg_id in (
        m.Id.DIAG_GET_COUNTERS,
        m.Id.TBL_READ,
        m.Id.GP_SINK_TABLE_READ,
        m.Id.DIAG_GET_NEIGHBORS,
        m.Id.DIAG_GET_CHILDREN,
        m.Id.NWK_ACTIVE_SCAN,
        m.Id.GP_PROXY_TABLE_READ,
        m.Id.FW_GET_SLOTS,
        m.Id.SYS_NEGOTIATE,
    ):
        return 640
    return _DEFAULT_RESPONSE


class _Budget:
    """A weighted semaphore."""

    def __init__(self, capacity: int) -> None:
        self.capacity = capacity
        self.used = 0
        self._cond = asyncio.Condition()

    async def acquire(self, weight: int) -> int:
        weight = min(weight, self.capacity)
        async with self._cond:
            await self._cond.wait_for(lambda: self.used + weight <= self.capacity)
            self.used += weight
        return weight

    async def release(self, weight: int) -> None:
        async with self._cond:
            self.used -= weight
            self._cond.notify_all()


class ZrhpError(Exception):
    """A ZRHP request failed."""

    def __init__(self, msg_id: int, status: Status | int, text: str | None = None) -> None:
        self.msg_id = msg_id
        self.status = status
        super().__init__(text or f"{m.name_of(msg_id)} failed: {_status_name(status)}")


class LinkResetError(ZrhpError):
    """The session reset before the response arrived (outcome unknown)."""


class SessionLost(ConnectionError):
    """The link to the NCP is down and was not re-established in time."""


def _status_name(status: Status | int) -> str:
    return status.name if isinstance(status, Status) else f"0x{status:02X}"


@dataclasses.dataclass
class SessionInfo:
    """What the NCP said in the last handshake."""

    ncp_cookie: int
    ready: Any  # EvtNcpReady
    negotiate: Any  # SysNegotiateRsp
    change: PeerChange

    @property
    def caps(self) -> NcpCaps:
        return NcpCaps(self.negotiate.ncp_caps & ((1 << 23) - 1))

    def capacity(self, cap: Capacity, default: int = 0) -> int:
        for c in self.negotiate.capacities:
            if c.id == cap:
                return c.value
        return default

    @property
    def fw_version(self) -> str:
        return self.negotiate.fw.decode(errors="replace")


@dataclasses.dataclass
class _Pending:
    msg_id: int
    tid: int
    endpoint: Endpoint
    message: m.Message
    future: asyncio.Future
    unknown: bool = False  # the carrying frame failed with LINK_RESET
    idempotent_retry: bool = True
    unsent: bool = False  # still queued when the session reset


EventHandler = Callable[[m.Message, Struct | None], None]
RequestHandler = Callable[[m.Message, Struct | None], Awaitable[bytes]]
SessionHandler = Callable[[str, SessionInfo | None], None]


class ZrhpApi:
    """One host side of a ZRHP session."""

    def __init__(
        self,
        transport_factory: Callable[[], ByteTransport],
        *,
        link_config: LinkConfig | None = None,
        host_caps: int = HOST_CAPS,
        name: str | None = None,
        cookie_factory: Callable[[], int] | None = None,
        handshake_timeout: float = 5.0,
    ) -> None:
        self._transport_factory = transport_factory
        self._link_config = link_config or LinkConfig.desktop_host()
        self._host_caps = int(host_caps)
        self._name = (name or f"zigpy-zrhp/{__version__}").encode()[:32]
        self._cookie_factory = cookie_factory or _random_cookie
        self._handshake_timeout = handshake_timeout
        self.transport: ByteTransport | None = None
        self.driver: LinkDriver | None = None
        self.session: SessionInfo | None = None
        self.last_ncp_cookie: int | None = None
        self._tid = 0
        self._pending: dict[tuple[int, int], _Pending] = {}
        self._ready = asyncio.Event()
        self._ncp_ready: asyncio.Future | None = None
        self._session_task: asyncio.Task | None = None
        self._pending_change: PeerChange = PeerChange.NEW
        self._event_handlers: list[EventHandler] = []
        self._session_handlers: list[SessionHandler] = []
        self._request_handler: RequestHandler | None = None
        self._closing = False
        self._host_cookie_changed = False
        self._budgets: dict[Endpoint, _Budget] = {}
        self._reconnect_task: asyncio.Task | None = None
        self.counters: dict[str, int] = {
            "msg_bad_batch": 0,
            "protocol_errors": 0,
            "retries_after_resync": 0,
            "lost_after_restart": 0,
            "port_reopened": 0,
        }

    # --- Registration -------------------------------------------------------

    def add_event_handler(self, handler: EventHandler) -> None:
        self._event_handlers.append(handler)

    def add_session_handler(self, handler: SessionHandler) -> None:
        """``handler(state, info)`` with state ``lost``/``ready``/``port_lost``."""
        self._session_handlers.append(handler)

    def set_request_handler(self, handler: RequestHandler) -> None:
        """Answer NCP-originated requests (``TBL_LOOKUP``, ``TBL_WRITEBACK``)."""
        self._request_handler = handler

    # --- Lifecycle ----------------------------------------------------------

    @property
    def is_ready(self) -> bool:
        return self._ready.is_set()

    async def connect(self) -> SessionInfo:
        """Open the port and complete handshake + negotiation; side-effect free on failure."""
        self._closing = False
        transport = self._transport_factory()
        transport.on_lost = self._on_port_lost
        await transport.open()
        self.transport = transport
        try:
            self.driver = LinkDriver(
                transport, self._link_config, self._cookie_factory(), self._on_link_event
            )
            self.driver.start(ResetReason.HOST_OPEN)
            await self.wait_ready(self._handshake_timeout)
        except BaseException:
            await self.disconnect()
            raise
        assert self.session is not None
        return self.session

    async def disconnect(self) -> None:
        self._closing = True
        self._ready.clear()
        for task in (self._session_task, self._reconnect_task):
            if task is not None and not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
        self._session_task = self._reconnect_task = None
        if self.driver is not None:
            await self.driver.stop()
            self.driver = None
        if self.transport is not None:
            await self.transport.close()
            self.transport = None
        self._fail_all(SessionLost("disconnected"))

    async def wait_ready(self, timeout: float | None) -> None:
        try:
            async with asyncio.timeout(timeout):
                await self._ready.wait()
        except TimeoutError:
            raise SessionLost("no ZRHP session with the NCP") from None

    async def reopen(self) -> None:
        """Reopen the port (USJ re-enumeration) and redo the handshake."""
        old = self.transport
        if old is not None:
            with contextlib.suppress(Exception):
                await old.close()
        transport = self._transport_factory()
        transport.on_lost = self._on_port_lost
        await transport.open()
        self.transport = transport
        assert self.driver is not None
        self.driver.transport = transport
        self._session_lost("port_reopened")
        self._host_cookie_changed = True
        self.driver.restart(self._cookie_factory(), ResetReason.HOST_OPEN)
        self.counters["port_reopened"] += 1

    async def hard_reset(self) -> None:
        """Reset the NCP through DTR/RTS (spec 11.3)."""
        if self.transport is not None:
            await self.transport.hard_reset()

    # --- Requests -----------------------------------------------------------

    def _next_tid(self) -> int:
        while True:
            self._tid = (self._tid + 1) & 0xFFFF
            if self._tid and all(k[1] != self._tid for k in self._pending):
                return self._tid

    async def request(
        self,
        body: Struct,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        allow: tuple[int, ...] = (Status.SUCCESS,),
        wait_session: float | None = 30.0,
        retry: bool = True,
    ) -> tuple[Status | int, Struct | None]:
        """Send a request and return ``(status, response body)``.

        Raises :class:`ZrhpError` unless the status is in ``allow``.
        """
        msg_id = body.MSG_ID  # type: ignore[attr-defined]
        payload = body.serialize()
        rsp = await self.request_raw(
            msg_id, payload, timeout=timeout, wait_session=wait_session, retry=retry
        )
        status, decoded = m.decode_response(msg_id, rsp)
        if status not in allow:
            raise ZrhpError(msg_id, status)
        return status, decoded

    async def request_raw(
        self,
        msg_id: int,
        payload: bytes = b"",
        *,
        timeout: float = DEFAULT_TIMEOUT,
        wait_session: float | None = 30.0,
        retry: bool = True,
        on_sent: Callable[[int], None] | None = None,
    ) -> bytes:
        """Send a raw request; returns the raw response payload (status first)."""
        endpoint = m.home_endpoint(msg_id)
        if endpoint is None:
            raise ValueError(f"no home endpoint for 0x{msg_id:04X}")
        if len(payload) > m.MAX_MESSAGE_PAYLOAD:
            raise ValueError("payload too large")
        if not self._ready.is_set():
            if self.driver is None or self._closing:
                raise SessionLost("not connected")
            await self.wait_ready(wait_session)
        loop = asyncio.get_running_loop()
        budget = self._budgets.setdefault(endpoint, _Budget(RESPONSE_BUDGET))
        try:
            async with asyncio.timeout(timeout):
                weight = await budget.acquire(_expected_response(msg_id, payload))
        except TimeoutError:
            raise ZrhpError(msg_id, Status.TIMEOUT, f"{m.name_of(msg_id)} timed out") from None
        tid = self._next_tid()
        msg = m.Message(Kind.REQUEST, msg_id, tid, payload)
        pending = _Pending(msg_id, tid, endpoint, msg, loop.create_future(), idempotent_retry=retry)
        self._pending[(msg_id, tid)] = pending
        if on_sent is not None:
            on_sent(tid)
        try:
            if self.driver is None:
                raise SessionLost("not connected")
            self.driver.send(endpoint, msg.serialize())
            async with asyncio.timeout(timeout):
                return await pending.future
        except TimeoutError:
            raise ZrhpError(msg_id, Status.TIMEOUT, f"{m.name_of(msg_id)} timed out") from None
        finally:
            self._pending.pop((msg_id, tid), None)
            await budget.release(weight)

    def send_response(self, endpoint: Endpoint, msg_id: int, tid: int, payload: bytes) -> None:
        if self.driver is not None:
            self.driver.send(endpoint, m.Message(Kind.RESPONSE, msg_id, tid, payload).serialize())

    def _fail_all(self, exc: Exception) -> None:
        for p in list(self._pending.values()):
            if not p.future.done():
                p.future.set_exception(exc)
        self._pending.clear()

    # --- Link events --------------------------------------------------------

    def _on_link_event(self, ev: LinkEvent) -> None:
        if isinstance(ev, Data):
            self._on_data(ev.endpoint, ev.payload)
        elif isinstance(ev, TxFailed):
            self._on_tx_failed(ev)
        elif isinstance(ev, PeerReset):
            LOGGER.info("NCP link reset: %s (cookie 0x%08X)", ev.change.value, ev.cookie)
            self._pending_change = ev.change
            self._session_lost(f"peer_{ev.change.value}")
        elif isinstance(ev, (LinkDown, LinkFailed)):
            LOGGER.warning("ZRHP link %s", "down" if isinstance(ev, LinkDown) else "failed")
            self._session_lost("link_down")
        elif isinstance(ev, Established):
            LOGGER.debug("ZRHP session established: %s", ev.session)
            self._ncp_ready = asyncio.get_running_loop().create_future()
            if self._session_task is not None and not self._session_task.done():
                self._session_task.cancel()
            self._session_task = asyncio.get_running_loop().create_task(
                self._negotiate_session(ev, self._ncp_ready)
            )

    def _session_lost(self, reason: str) -> None:
        was_ready = self._ready.is_set()
        self._ready.clear()
        if self.driver is not None:
            # Nothing may precede SYS_NEGOTIATE in the next session (5.5).
            unsent = {
                (msg.msg_id, msg.tid)
                for _, raw in self.driver.queues.clear()
                for msg in _safe_batch(raw)
                if msg.kind is Kind.REQUEST
            }
            for key in unsent:
                p = self._pending.get(key)
                if p is not None:
                    p.unsent = True
        if was_ready:
            for h in self._session_handlers:
                h("lost", None)

    def _on_tx_failed(self, ev: TxFailed) -> None:
        try:
            msgs = m.parse_batch(ev.payload)
        except m.BatchError:
            return
        for msg in msgs:
            if msg.kind is not Kind.REQUEST:
                continue
            p = self._pending.get((msg.msg_id, msg.tid))
            if p is None or p.future.done():
                continue
            if ev.reason is TxFailure.REJECTED:
                p.future.set_exception(
                    ZrhpError(msg.msg_id, Status.LINK_REJECTED, "frame rejected by the NCP")
                )
            else:
                p.unknown = True

    def _on_data(self, endpoint: Endpoint, payload: bytes) -> None:
        try:
            msgs = m.parse_batch(payload)
        except m.BatchError as e:
            self.counters["msg_bad_batch"] += 1
            LOGGER.warning("Malformed batch on %s: %s", endpoint.name, e)
            return
        for msg in msgs:
            if msg.kind is Kind.RESPONSE:
                p = self._pending.get((msg.msg_id, msg.tid))
                if p is not None and not p.future.done():
                    p.future.set_result(msg.payload)
                else:
                    LOGGER.debug("Unmatched response %s tid=%d", m.name_of(msg.msg_id), msg.tid)
            elif msg.kind is Kind.EVENT:
                self._on_event(msg)
            else:
                self._on_ncp_request(endpoint, msg)

    def _on_event(self, msg: m.Message) -> None:
        try:
            body = m.decode_message(msg)
        except CodecError as e:
            self.counters["protocol_errors"] += 1
            LOGGER.warning(
                "Undecodable event %s: %s (%s)", m.name_of(msg.msg_id), e, msg.payload.hex()
            )
            return
        if msg.msg_id == m.Id.EVT_NCP_READY:
            fut = self._ncp_ready
            if fut is not None and not fut.done():
                fut.set_result(body)
            return
        if msg.msg_id == m.Id.EVT_PROTOCOL_ERROR:
            self.counters["protocol_errors"] += 1
            LOGGER.warning("NCP reports a protocol error: %r", body)
        for h in self._event_handlers:
            try:
                h(msg, body)
            except Exception:
                LOGGER.exception("Event handler failed for %s", m.name_of(msg.msg_id))

    def _on_ncp_request(self, endpoint: Endpoint, msg: m.Message) -> None:
        async def answer() -> None:
            try:
                body = m.decode_message(msg)
            except CodecError:
                payload = bytes([Status.INVALID_PARAMETER])
            else:
                if self._request_handler is None or body is None:
                    payload = bytes([Status.UNSUPPORTED_COMMAND])
                else:
                    try:
                        payload = await self._request_handler(msg, body)
                    except Exception:
                        LOGGER.exception("NCP request %s failed", m.name_of(msg.msg_id))
                        payload = bytes([Status.FAILURE])
            self.send_response(endpoint, msg.msg_id, msg.tid, payload)

        asyncio.get_running_loop().create_task(answer())

    # --- Session ------------------------------------------------------------

    async def _negotiate_session(self, ev: Established, ready: asyncio.Future) -> None:
        change = self._pending_change
        try:
            async with asyncio.timeout(self._handshake_timeout):
                ncp_ready = await ready
            # SYS_NEGOTIATE goes out before anything else, bypassing the gate.
            assert self.driver is not None
            loop = asyncio.get_running_loop()
            tid = self._next_tid()
            body = m.SysNegotiateReq(
                major_min=MAJOR, major_max=MAJOR, host_caps=self._host_caps, name=self._name
            )
            msg = m.Message(Kind.REQUEST, m.Id.SYS_NEGOTIATE, tid, body.serialize())
            p = _Pending(m.Id.SYS_NEGOTIATE, tid, Endpoint.SYSTEM, msg, loop.create_future())
            self._pending[(p.msg_id, tid)] = p
            try:
                self.driver.send(Endpoint.SYSTEM, msg.serialize())
                async with asyncio.timeout(self._handshake_timeout):
                    raw = await p.future
            finally:
                self._pending.pop((p.msg_id, tid), None)
            status, rsp = m.decode_response(m.Id.SYS_NEGOTIATE, raw)
            if status != Status.SUCCESS or rsp is None:
                raise ZrhpError(m.Id.SYS_NEGOTIATE, status)
            if rsp.major != MAJOR:
                raise ZrhpError(m.Id.SYS_NEGOTIATE, Status.VERSION_MISMATCH)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            LOGGER.warning("ZRHP session setup failed: %r", e)
            if self.driver is not None and not self._closing:
                # Restart the handshake; the NCP repeats EVT_NCP_READY.
                self.driver.restart(self.driver.link.cookie, ResetReason.PROTOCOL_ERROR)
            return
        if change is PeerChange.NEW and self.last_ncp_cookie is not None:
            change = (
                PeerChange.RESYNC
                if ncp_ready.ncp_cookie == self.last_ncp_cookie
                else PeerChange.RESTARTED
            )
        if self.last_ncp_cookie is not None and ncp_ready.ncp_cookie != self.last_ncp_cookie:
            change = PeerChange.RESTARTED
        self.last_ncp_cookie = ncp_ready.ncp_cookie
        self.session = SessionInfo(ncp_ready.ncp_cookie, ncp_ready, rsp, change)
        self._pending_change = PeerChange.NEW
        self._resolve_unknown(change)
        self._ready.set()
        LOGGER.info(
            "ZRHP session ready: NCP fw %s, cookie 0x%08X, network_state %d (%s)",
            self.session.fw_version,
            ncp_ready.ncp_cookie,
            ncp_ready.network_state,
            change.value,
        )
        for h in self._session_handlers:
            h("ready", self.session)

    def _resolve_unknown(self, change: PeerChange) -> None:
        """Requests still pending when the session reset (spec 6.5)."""
        cache_valid = change is PeerChange.RESYNC and not self._host_cookie_changed
        self._host_cookie_changed = False
        for p in list(self._pending.values()):
            if p.future.done() or p.msg_id == m.Id.SYS_NEGOTIATE:
                continue
            assert self.driver is not None
            if p.unsent and not p.unknown:
                p.unsent = False
                self.driver.send(p.endpoint, p.message.serialize())
            elif cache_valid and p.idempotent_retry:
                # The NCP retry cache answers it if it already ran.
                self.counters["retries_after_resync"] += 1
                p.unknown = False
                p.message.retry = True
                assert self.driver is not None
                self.driver.send(p.endpoint, p.message.serialize())
            else:
                self.counters["lost_after_restart"] += 1
                p.future.set_exception(
                    LinkResetError(p.msg_id, Status.LINK_RESET, "NCP restarted, delivery unknown")
                )

    def _on_port_lost(self, exc: Exception | None) -> None:
        if self._closing:
            return
        LOGGER.warning("Serial port lost: %r", exc)
        self._session_lost("port_lost")
        for h in self._session_handlers:
            h("port_lost", None)


def _safe_batch(raw: bytes) -> list[m.Message]:
    try:
        return m.parse_batch(raw)
    except m.BatchError:
        return []


def _random_cookie() -> int:
    while True:
        c = secrets.randbits(32)
        if c:
            return c
