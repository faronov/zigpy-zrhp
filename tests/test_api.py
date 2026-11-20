"""Session, requests, resync retries and NCP restarts through the asyncio stack."""

from __future__ import annotations

import asyncio
import random

import pytest

from zigpy_zrhp import messages as m
from zigpy_zrhp.api import LinkResetError, SessionLost, ZrhpApi, ZrhpError
from zigpy_zrhp.link import PeerChange
from zigpy_zrhp.sim.ncp import SWALLOW, SimNcp
from zigpy_zrhp.transport import MemoryTransport
from zigpy_zrhp.types import Status


async def make(
    sim: SimNcp | None = None, **kw
) -> tuple[ZrhpApi, SimNcp, MemoryTransport, MemoryTransport]:
    host_t, ncp_t = MemoryTransport.pair()
    sim = sim or SimNcp()
    await ncp_t.open()
    sim.attach(ncp_t)
    api = ZrhpApi(lambda: host_t, **kw)
    await api.connect()
    return api, sim, host_t, ncp_t


async def test_connect_negotiate_echo() -> None:
    api, sim, *_ = await make()
    try:
        assert api.session is not None
        assert api.session.ready.ncp_cookie == sim.cookie
        assert api.session.fw_version == "0.1.0-sim"
        _, rsp = await api.request(m.SysEchoReq(data=b"hello"))
        assert rsp.data == b"hello"
        assert sim.host_caps & 0x0F == 0x0F
        # Many requests in flight at once.
        results = await asyncio.gather(
            *(api.request(m.SysEchoReq(data=bytes([i]) * 40)) for i in range(64))
        )
        assert [r[1].data for r in results] == [bytes([i]) * 40 for i in range(64)]
    finally:
        await api.disconnect()
        await sim.stop()


async def test_connect_fails_cleanly_without_ncp() -> None:
    host_t, _ = MemoryTransport.pair()
    api = ZrhpApi(lambda: host_t, handshake_timeout=0.3)
    with pytest.raises(SessionLost):
        await api.connect()
    assert api.driver is None and api.transport is None


async def test_error_status_and_unsupported() -> None:
    api, sim, *_ = await make()
    try:
        with pytest.raises(ZrhpError) as exc:
            await api.request(m.NwkPermitJoinReq(duration_s=10, target=0xFFFC, flags=1))
        assert exc.value.status == Status.INVALID_STATE  # no network
        raw = await api.request_raw(0x0F70 & 0x07FF | 0x0700, b"")  # unknown DIAG id
        assert raw[0] == Status.UNSUPPORTED_COMMAND
    finally:
        await api.disconnect()
        await sim.stop()


async def test_ncp_restart_fails_pending_and_renegotiates() -> None:
    api, sim, *_ = await make()
    states: list[tuple[str, object]] = []
    api.add_session_handler(lambda s, info: states.append((s, info)))
    try:
        sim.on_request = lambda msg: SWALLOW if msg.msg_id == m.Id.SYS_ECHO else None  # swallow
        # An echo that the NCP never answers; then the NCP reboots.
        task = asyncio.create_task(api.request(m.SysEchoReq(data=b"x"), timeout=5))
        await asyncio.sleep(0.05)
        sim.on_request = None
        old = sim.cookie
        await sim.reboot()
        with pytest.raises(LinkResetError):
            await task
        await api.wait_ready(5)
        assert api.session.ready.ncp_cookie == sim.cookie != old
        assert api.session.change is PeerChange.RESTARTED
        assert [s for s, _ in states] == ["lost", "ready"]
        _, rsp = await api.request(m.SysEchoReq(data=b"after"))
        assert rsp.data == b"after"
    finally:
        await api.disconnect()
        await sim.stop()


async def test_resync_retries_with_retry_flag() -> None:
    api, sim, host_t, _ = await make()
    try:
        drop = {"on": False}
        original = host_t.write

        def write(data: bytes) -> None:
            if not drop["on"]:
                original(data)

        host_t.write = write  # type: ignore[method-assign]
        drop["on"] = True
        task = asyncio.create_task(api.request(m.SysEchoReq(data=b"r"), timeout=10))
        await asyncio.sleep(0.05)
        # NCP loses sync without rebooting (same cookie).
        assert sim.driver is not None
        sim.driver.link.open(sim.driver._clock())
        sim.driver.kick()
        drop["on"] = False
        _, rsp = await task
        assert rsp.data == b"r"
        assert api.session.change is PeerChange.RESYNC
        assert api.counters["retries_after_resync"] == 1
        retried = [msg for mid, msg in sim.requests if mid == m.Id.SYS_ECHO]
        assert retried[-1].retry
    finally:
        await api.disconnect()
        await sim.stop()


async def test_noisy_line_request_storm() -> None:
    rng = random.Random(7)

    def noise(data: bytes) -> bytes:
        out = bytearray(data)
        for i in range(len(out)):
            if rng.random() < 3e-4:
                out[i] ^= 1 << rng.randrange(8)
        if rng.random() < 0.01:
            return bytes(out[: len(out) // 2])  # truncated chunk
        return bytes(out)

    api, sim, host_t, ncp_t = await make()
    host_t.mangle = noise
    ncp_t.mangle = noise
    try:
        results = await asyncio.gather(
            *(api.request(m.SysEchoReq(data=bytes([i % 256]) * 50), timeout=20) for i in range(300))
        )
        assert all(r[1].data == bytes([i % 256]) * 50 for i, r in enumerate(results))
        c = api.driver.link.counters
        assert c.rx_bad_frame + sim.driver.link.counters.rx_bad_frame > 0
    finally:
        await api.disconnect()
        await sim.stop()


async def test_port_reopen() -> None:
    api, sim, host_t, _ = await make()
    try:
        old_cookie = api.driver.link.cookie
        host_t.drop()
        await asyncio.sleep(0)
        assert not api.is_ready
        await api.reopen()
        await api.wait_ready(5)
        assert api.driver.link.cookie != old_cookie
        assert api.session.change is PeerChange.RESYNC  # the NCP did not reboot
        _, rsp = await api.request(m.SysEchoReq(data=b"ok"))
        assert rsp.data == b"ok"
    finally:
        await api.disconnect()
        await sim.stop()
