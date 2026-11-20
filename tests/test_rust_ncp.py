"""The library against the Rust NCP (``apps/ncp-coordinator`` example ``ncp_sim``).

The Rust process runs the real link layer, message dispatch, formation and
backup code of the zigbee-rs NCP over stdin/stdout, with a mock radio. Set
``ZRHP_NCP_SIM`` to the binary (built with ``cargo build --manifest-path
apps/ncp-coordinator/Cargo.toml --example ncp_sim`` on the ``zrhp-ncp-sim``
branch of faronov/zigbee-rs); the tests are skipped otherwise.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import random

import pytest
import zigpy.exceptions
import zigpy.types as t

from zigpy_zrhp import messages as m
from zigpy_zrhp.api import ZrhpApi
from zigpy_zrhp.transport import ByteTransport
from zigpy_zrhp.types import NcpCaps, Status
from zigpy_zrhp.zigbee.application import ControllerApplication

from .app_bench import make_config

BINARY = os.environ.get("ZRHP_NCP_SIM")
pytestmark = pytest.mark.skipif(
    not BINARY or not os.path.exists(BINARY), reason="ZRHP_NCP_SIM not set"
)


class ProcessTransport(ByteTransport):
    """The Rust NCP as a child process; stdin/stdout carry the ZRHP bytes."""

    def __init__(self, proc_holder: dict, mangle=None) -> None:
        super().__init__()
        self._holder = proc_holder
        self.mangle = mangle
        self._task: asyncio.Task | None = None

    async def open(self) -> None:
        proc = self._holder.get("proc")
        if proc is None or proc.returncode is not None:
            proc = await asyncio.create_subprocess_exec(
                BINARY,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            self._holder["proc"] = proc
        self._proc = proc
        self._task = asyncio.get_running_loop().create_task(self._reader())

    async def _reader(self) -> None:
        assert self._proc.stdout is not None
        while True:
            data = await self._proc.stdout.read(4096)
            if not data:
                self.on_lost(ConnectionError("NCP process exited"))
                return
            self.on_data(data)

    def write(self, data: bytes) -> None:
        if self.mangle is not None:
            data = self.mangle(data)
        stdin = self._proc.stdin
        if stdin is not None and not stdin.is_closing():
            stdin.write(data)

    async def close(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task


async def kill(holder: dict) -> None:
    proc = holder.get("proc")
    if proc is not None and proc.returncode is None:
        proc.kill()
        await proc.wait()


async def test_session_and_echo_storm() -> None:
    holder: dict = {}
    api = ZrhpApi(lambda: ProcessTransport(holder))
    try:
        session = await api.connect()
        assert session.negotiate.major == 1
        assert session.caps & NcpCaps.KEY_EXPORT
        assert session.caps & NcpCaps.BACKUP_RESTORE
        assert session.ready.network_state == 0
        results = await asyncio.gather(
            *(api.request(m.SysEchoReq(data=bytes([i]) * 60), timeout=20) for i in range(200))
        )
        assert all(r[1].data == bytes([i]) * 60 for i, r in enumerate(results))
        status, _ = await api.request(m.NwkInitReq(), allow=(Status.NOT_FORMED,))
        assert status == Status.NOT_FORMED
    finally:
        await api.disconnect()
        await kill(holder)


async def test_noisy_line_against_rust_link() -> None:
    rng = random.Random(3)

    def noise(data: bytes) -> bytes:
        out = bytearray(data)
        for i in range(len(out)):
            if rng.random() < 2e-4:
                out[i] ^= 1 << rng.randrange(8)
        return bytes(out)

    holder: dict = {}
    api = ZrhpApi(lambda: ProcessTransport(holder, mangle=noise))
    try:
        await api.connect()
        results = await asyncio.gather(
            *(api.request(m.SysEchoReq(data=bytes([i % 256]) * 64), timeout=30) for i in range(300))
        )
        assert all(r[1].data == bytes([i % 256]) * 64 for i, r in enumerate(results))
        _, counters = await api.request(m.DiagGetCountersReq(group_mask=0x01))
        ncp = {c.id: c.value for c in counters.counters}
        assert ncp.get(0x0113, 0) > 0  # the Rust receiver saw (and recovered) bad frames
    finally:
        await api.disconnect()
        await kill(holder)


class RustApp(ControllerApplication):
    holder: dict

    def _create_transport(self, baudrate, flow):  # type: ignore[override]
        return ProcessTransport(self.holder)


async def _app(tmp_path, holder: dict, *, auto_form: bool) -> RustApp:
    class App(RustApp):
        pass

    App.holder = holder
    app = App(make_config(tmp_path, connect_timeout=5.0, resume_budget=3.0))
    await app._load_db()
    try:
        await app.startup(auto_form=auto_form)
    except BaseException:
        await app.shutdown()
        raise
    return app


async def test_zigpy_forms_backs_up_and_restores(tmp_path) -> None:
    holder: dict = {}
    app = await _app(tmp_path / "a", holder, auto_form=True)
    try:
        ni = app.state.network_info
        assert ni.pan_id not in (0x0000, 0xFFFF)
        assert app.state.node_info.ieee == t.EUI64(
            bytes([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80])
        )
        backup = await app.backups.create_backup(load_devices=True)
        assert backup.is_complete()
        assert backup.network_info.stack_specific["zigbee_rs"]["nwk_frame_counter_limit"] >= 1024
        info = await app._get_info()
        assert info.state == 2
        await app.permit(5)
    finally:
        await app.shutdown()
        await kill(holder)

    # A factory-new NCP (new process) gets the backup restored by zigpy.
    holder2: dict = {}

    class App2(RustApp):
        pass

    App2.holder = holder2
    app2 = App2(make_config(tmp_path / "b"))
    await app2._load_db()
    try:
        await app2.connect()
        with pytest.raises(zigpy.exceptions.NetworkNotFormed):
            await app2.load_network_info()
        await app2.backups.restore_backup(backup)
        await app2.initialize()
        restored = app2.backups.from_network_state()
        assert restored.is_compatible_with(backup)
        # Counters only move forward (zigpy +10 000 NWK, library +10 000 APS).
        assert (
            restored.network_info.network_key.tx_counter
            >= backup.network_info.network_key.tx_counter + 10_000
        )
    finally:
        await app2.shutdown()
        await kill(holder2)


async def test_ncp_losing_its_network_is_not_resumed(tmp_path) -> None:
    holder: dict = {}
    app = await _app(tmp_path, holder, auto_form=True)
    lost: list[Exception] = []
    app.add_listener(type("L", (), {"connection_lost": lambda s, e: lost.append(e)})())
    try:
        await kill(holder)  # the RAM-only simulator forgets everything
        await asyncio.wait_for(_until(lambda: lost), 20)
        assert lost
    finally:
        await app.shutdown()
        await kill(holder)


async def _until(pred) -> None:
    while not pred():
        await asyncio.sleep(0.05)
