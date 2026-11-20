"""Byte transports and the asyncio link driver.

:class:`LinkDriver` runs a :class:`~zigpy_zrhp.link.Link` on a real monotonic
clock over a :class:`ByteTransport` (a serial port through ``zigpy.serial`` /
serialx, or an in-memory pipe in tests).
"""

from __future__ import annotations

import abc
import asyncio
import collections
from collections.abc import Callable
import contextlib
import logging
import sys
import time
from typing import Any

from .frame import ResetReason
from .link import Link, LinkConfig, LinkEvent
from .types import Endpoint

LOGGER = logging.getLogger(__name__)


def now_us() -> int:
    return time.monotonic_ns() // 1000


class ByteTransport(abc.ABC):
    """A full-duplex byte stream (USB-Serial-JTAG CDC or UART)."""

    def __init__(self) -> None:
        self.on_data: Callable[[bytes], None] = lambda data: None
        self.on_lost: Callable[[Exception | None], None] = lambda exc: None

    @abc.abstractmethod
    async def open(self) -> None: ...

    @abc.abstractmethod
    def write(self, data: bytes) -> None: ...

    @abc.abstractmethod
    async def close(self) -> None: ...

    async def set_lines(self, *, dtr: bool, rts: bool) -> None:  # noqa: B027
        """Set DTR and RTS together (spec 11.3)."""

    async def hard_reset(self) -> None:
        """``(0,0) -> (1,0) for >= 10 ms -> (0,0)`` (spec 11.3)."""
        await self.set_lines(dtr=False, rts=False)
        await self.set_lines(dtr=False, rts=True)
        await asyncio.sleep(0.02)
        await self.set_lines(dtr=False, rts=False)
        await asyncio.sleep(0.05)
        await self.set_lines(dtr=True, rts=True)

    def flush_input(self) -> None:  # noqa: B027
        """Discard OS input buffers (spec 5.5 step 1)."""


class _SerialProtocol(asyncio.Protocol):
    def __init__(self, owner: SerialTransport) -> None:
        self._owner = owner

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._owner._transport = transport  # type: ignore[assignment]

    def data_received(self, data: bytes) -> None:
        self._owner.on_data(data)

    def connection_lost(self, exc: Exception | None) -> None:
        owner = self._owner
        owner._transport = None
        if not owner._closing:
            owner.on_lost(exc or ConnectionError("serial port closed"))


class SerialTransport(ByteTransport):
    """A serial port through ``zigpy.serial`` (serialx)."""

    def __init__(self, path: str, baudrate: int, flow_control: str | None) -> None:
        super().__init__()
        self.path = path
        self.baudrate = baudrate
        self.flow_control = flow_control
        self._transport: asyncio.Transport | None = None
        self._closing = False

    async def open(self) -> None:
        import zigpy.serial

        self._closing = False
        loop = asyncio.get_running_loop()
        await zigpy.serial.create_serial_connection(
            loop,
            lambda: _SerialProtocol(self),
            url=self.path,
            baudrate=self.baudrate,
            flow_control=self.flow_control,
        )
        if self._transport is None:  # pragma: no cover - serialx always connects first
            raise ConnectionError(f"Failed to open {self.path}")

    def write(self, data: bytes) -> None:
        if self._transport is not None:
            self._transport.write(data)

    async def close(self) -> None:
        self._closing = True
        transport, self._transport = self._transport, None
        if transport is not None:
            transport.close()
            await asyncio.sleep(0)

    def flush_input(self) -> None:
        serial = getattr(self._transport, "serial", None) or getattr(
            self._transport, "_serial", None
        )
        with contextlib.suppress(Exception):
            serial.reset_input_buffer()  # type: ignore[union-attr]

    async def set_lines(self, *, dtr: bool, rts: bool) -> None:
        """Both lines with one ``TIOCMSET`` where possible (spec 11.3)."""
        transport = self._transport
        if transport is None:
            return
        fileno = None
        for attr in ("fileno", "_fileno"):
            fd = getattr(transport, attr, None)
            fd = fd() if callable(fd) else fd
            if isinstance(fd, int):
                fileno = fd
                break
        if fileno is not None and sys.platform != "win32":
            import array
            import fcntl
            import termios

            buf = array.array("i", [0])
            fcntl.ioctl(fileno, termios.TIOCMGET, buf)
            value = buf[0] & ~(termios.TIOCM_DTR | termios.TIOCM_RTS)
            value |= (termios.TIOCM_DTR if dtr else 0) | (termios.TIOCM_RTS if rts else 0)
            fcntl.ioctl(fileno, termios.TIOCMSET, array.array("i", [value]))
            return
        setter = getattr(transport, "set_modem_pins", None)
        if setter is not None:  # serialx; clears and sets in two ioctls at most
            result = setter(dtr=dtr, rts=rts)
            if asyncio.iscoroutine(result):
                await result


class MemoryTransport(ByteTransport):
    """One end of an in-memory byte pipe (tests and the simulator)."""

    def __init__(self) -> None:
        super().__init__()
        self.peer: MemoryTransport | None = None
        self.is_open = False
        self.written = 0
        self.lines = (True, True)
        self.on_lines: Callable[[bool, bool], None] | None = None
        #: Optional fault injector: maps outgoing bytes to delivered bytes.
        self.mangle: Callable[[bytes], bytes] | None = None
        self.open_error: Exception | None = None

    @classmethod
    def pair(cls) -> tuple[MemoryTransport, MemoryTransport]:
        a, b = cls(), cls()
        a.peer, b.peer = b, a
        return a, b

    async def open(self) -> None:
        if self.open_error is not None:
            raise self.open_error
        self.is_open = True

    def write(self, data: bytes) -> None:
        if not self.is_open:
            return
        self.written += len(data)
        if self.mangle is not None:
            data = self.mangle(data)
        peer = self.peer
        if peer is not None and peer.is_open and data:
            asyncio.get_running_loop().call_soon(peer.on_data, bytes(data))

    async def close(self) -> None:
        self.is_open = False

    def drop(self, exc: Exception | None = None) -> None:
        """Simulate the port disappearing (USJ re-enumeration)."""
        self.is_open = False
        self.on_lost(exc or ConnectionError("port vanished"))

    async def set_lines(self, *, dtr: bool, rts: bool) -> None:
        self.lines = (dtr, rts)
        if self.on_lines is not None:
            self.on_lines(dtr, rts)


class EndpointQueues:
    """Per-endpoint message queues feeding the link (opportunistic batching)."""

    def __init__(self) -> None:
        self._q: dict[Endpoint, collections.deque[bytes]] = {
            ep: collections.deque() for ep in Endpoint if ep is not Endpoint.LINK
        }

    def push(self, endpoint: Endpoint, message: bytes) -> None:
        self._q[endpoint].append(message)

    def ready(self, endpoint: Endpoint) -> bool:
        return bool(self._q.get(endpoint))

    def fill(self, endpoint: Endpoint, mtu: int) -> bytes:
        q = self._q[endpoint]
        out = bytearray()
        while q and len(out) + len(q[0]) <= mtu:
            out += q.popleft()
        return bytes(out)

    def clear(self) -> list[tuple[Endpoint, bytes]]:
        out = [(ep, m) for ep, q in self._q.items() for m in q]
        for q in self._q.values():
            q.clear()
        return out

    def pending(self) -> int:
        return sum(len(q) for q in self._q.values())


class LinkDriver:
    """Runs a :class:`Link` over a :class:`ByteTransport` on the event loop."""

    def __init__(
        self,
        transport: ByteTransport,
        config: LinkConfig,
        cookie: int,
        on_event: Callable[[LinkEvent], None],
        *,
        txw: int = 32,
        rxw: int = 32,
        clock: Callable[[], int] = now_us,
    ) -> None:
        self.transport = transport
        self.link = Link(config, cookie, txw=txw, rxw=rxw)
        self.queues = EndpointQueues()
        self._on_event = on_event
        self._clock = clock
        self._wake = asyncio.Event()
        self._task: asyncio.Task | None = None
        self._rx_backlog = bytearray()
        transport.on_data = self._data_received

    def start(self, reason: ResetReason = ResetReason.HOST_OPEN) -> None:
        self.transport.flush_input()
        self.link.open(self._clock(), reason)
        if self._task is None:
            self._task = asyncio.get_running_loop().create_task(self._run())
        self.kick()

    def restart(self, cookie: int, reason: ResetReason = ResetReason.HOST_OPEN) -> None:
        """Re-run the handshake with a new cookie (port reopened)."""
        self.transport.on_data = self._data_received
        self.transport.flush_input()
        self._rx_backlog.clear()
        self.link.reopen(self._clock(), cookie, reason)
        self.kick()

    async def stop(self) -> None:
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    def kick(self) -> None:
        self._wake.set()

    def send(self, endpoint: Endpoint, message: bytes) -> None:
        self.queues.push(endpoint, message)
        self.kick()

    def _data_received(self, data: bytes) -> None:
        self._rx_backlog += data
        self._process_rx()
        self.kick()

    def _process_rx(self) -> None:
        now = self._clock()
        data = bytes(self._rx_backlog)
        self._rx_backlog.clear()
        off = 0
        while off < len(data):
            off += self.link.push_rx(data[off:], now)
            self._drain_events()
        self._drain_events()

    def _drain_events(self) -> None:
        while (ev := self.link.poll_event()) is not None:
            try:
                self._on_event(ev)
            except Exception:
                LOGGER.exception("Link event handler failed for %r", ev)

    def _flush_tx(self) -> None:
        now = self._clock()
        while (w := self.link.poll_transmit(now, self.queues)) is not None:
            self.transport.write(w)
        self._drain_events()

    async def _run(self) -> None:
        while True:
            self._wake.clear()
            try:
                self._flush_tx()
            except Exception:
                LOGGER.exception("Link transmit failed")
            deadline = self.link.next_deadline()
            if deadline is None:
                timeout: float | None = None
            else:
                timeout = max(0.0, (deadline - self._clock()) / 1e6)
                if deadline == 0:
                    timeout = 0.0
            if timeout == 0.0:
                await asyncio.sleep(0)
                continue
            with contextlib.suppress(TimeoutError):
                async with asyncio.timeout(timeout):
                    await self._wake.wait()

    def counters(self) -> dict[str, Any]:
        return self.link.counters.as_dict()
