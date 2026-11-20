"""Seamless NCP-reboot resume (spec 12.1, decision 5)."""

from __future__ import annotations

import asyncio

import zigpy.exceptions
import zigpy.types as t

from zigpy_zrhp import messages as m
from zigpy_zrhp.sim.ncp import SWALLOW, SimDevice, SimNcp

from .app_bench import Bench, start_app, stop, wait_for

DEV = bytes.fromhex("0c0b0afeff142e84")


async def _joined(app, sim):
    sim.join(SimDevice(ieee=DEV, nwk=0x2222))
    ieee = t.EUI64(DEV)
    await wait_for(lambda: ieee in app.devices and app.devices[ieee].model is not None, 10)
    return app.devices[ieee]


async def test_ncp_reboot_is_seamless(tmp_path) -> None:
    app, bench = await start_app(tmp_path)
    sim = bench.sim
    lost: list[Exception] = []
    app.add_listener(type("L", (), {"connection_lost": lambda s, e: lost.append(e)})())
    try:
        dev = await _joined(app, sim)
        await app.permit(120)
        limits_before = (sim.nwk_limit, sim.aps_limit)
        endpoints_before = dict(sim.endpoints)
        await sim.reboot(reason=3)
        assert not sim.running and not sim.endpoints
        # A request issued during the outage waits and then succeeds.
        await dev.endpoints[1].on_off.on()
        await wait_for(lambda: app._resumed.is_set(), 5)
        assert not lost
        assert sim.running
        assert sorted(sim.endpoints) == sorted(endpoints_before)
        assert sim.gp_config is not None and sim.gp_config.mode == 1
        # Permit join remainder replayed (decision 5, step 5).
        assert sim.permit_log[-1][0] > 100
        assert sim.gp_commissioning_until is not None
        # Counters never go backwards across the reboot.
        assert sim.nwk_current >= limits_before[0]
        assert app.state.counters["zrhp"]["ncp_resumed"].value == 1
    finally:
        await stop(app, bench)


async def test_inflight_send_fails_with_delivery_unknown(tmp_path) -> None:
    app, bench = await start_app(tmp_path)
    sim = bench.sim
    try:
        dev = await _joined(app, sim)
        sim.on_request = lambda msg: SWALLOW if msg.msg_id == m.Id.APS_DATA_REQUEST else None
        task = asyncio.create_task(dev.endpoints[1].on_off.on())
        await asyncio.sleep(0.05)
        sim.on_request = None
        await sim.reboot()
        # The library reports DeliveryError("delivery unknown"); zigpy's own
        # request retry then resends it after the resume.
        try:
            await task
        except zigpy.exceptions.DeliveryError as e:
            assert "unknown" in str(e) or "restarted" in str(e).lower()
        assert app._api.counters["lost_after_restart"] == 1
        await wait_for(lambda: app._resumed.is_set(), 5)
        await dev.endpoints[1].on_off.off()
    finally:
        await stop(app, bench)


async def test_changed_network_raises_connection_lost(tmp_path) -> None:
    app, bench = await start_app(tmp_path)
    sim = bench.sim
    lost: list[Exception] = []
    app.add_listener(type("L", (), {"connection_lost": lambda s, e: lost.append(e)})())
    try:
        sim.net.ext_pan_id = bytes(range(8))  # someone restored another network
        await sim.reboot()
        await wait_for(lambda: lost, 5)
        assert "epid" in str(lost[0])
    finally:
        await stop(app, bench)


async def test_table_epoch_change_raises_connection_lost(tmp_path) -> None:
    app, bench = await start_app(tmp_path)
    sim = bench.sim
    lost: list[Exception] = []
    app.add_listener(type("L", (), {"connection_lost": lambda s, e: lost.append(e)})())
    try:
        sim.table_epoch ^= 0x5A5A
        await sim.reboot()
        await wait_for(lambda: lost, 5)
        assert "epoch" in str(lost[0])
    finally:
        await stop(app, bench)


async def test_raised_key_seq_is_adopted(tmp_path) -> None:
    app, bench = await start_app(tmp_path)
    sim = bench.sim
    try:
        seq = app.state.network_info.network_key.seq
        sim.net.key_seq = (seq + 1) & 0xFF  # rotation completed during the outage
        sim.net.nwk_update_id = (sim.net.nwk_update_id + 1) & 0xFF
        await sim.reboot()
        await wait_for(
            lambda: app._resumed.is_set() and app.state.network_info.network_key.seq == seq + 1, 5
        )
        assert app.state.network_info.nwk_update_id == sim.net.nwk_update_id
    finally:
        await stop(app, bench)


async def test_link_resync_without_reboot(tmp_path) -> None:
    app, bench = await start_app(tmp_path)
    sim = bench.sim
    try:
        dev = await _joined(app, sim)
        inits = sum(1 for mid, _ in sim.requests if mid == m.Id.NWK_INIT)
        sim.driver.link.open(sim.driver._clock())  # NCP lost sync, same cookie
        sim.driver.kick()
        await dev.endpoints[1].on_off.toggle()
        await wait_for(lambda: app._resumed.is_set(), 5)
        # No reconciliation replay was needed.
        assert sum(1 for mid, _ in sim.requests if mid == m.Id.NWK_INIT) == inits
    finally:
        await stop(app, bench)


async def test_port_disappears_and_returns(tmp_path) -> None:
    app, bench = await start_app(tmp_path)
    sim = bench.sim
    try:
        dev = await _joined(app, sim)
        bench.host_end.drop()  # USJ re-enumeration
        await sim.reboot()  # the NCP was reset with it
        await dev.endpoints[1].on_off.on()
        assert app._api.counters["port_reopened"] >= 1
        assert app._resumed.is_set()
    finally:
        await stop(app, bench)


async def test_ncp_never_returns_gives_up_after_hard_reset(tmp_path) -> None:
    app, bench = await start_app(tmp_path, resume_budget=1.0)
    sim = bench.sim
    lost: list[Exception] = []
    lines: list[tuple[bool, bool]] = []
    app.add_listener(type("L", (), {"connection_lost": lambda s, e: lost.append(e)})())
    try:
        bench.host_end.on_lines = lambda dtr, rts: lines.append((dtr, rts))
        await sim.stop()  # dead NCP
        bench.ncp_end.is_open = False
        await wait_for(lambda: lost, 10)
        # The DTR/RTS reset sequence (0,0) -> (RTS=1, DTR=0) -> (0,0) was tried once.
        assert (False, True) in lines
        assert lines.index((False, True)) > lines.index((False, False))
    finally:
        await stop(app, bench)


async def test_silent_ncp_at_startup_gets_one_hard_reset(tmp_path) -> None:
    """An NCP left in its ROM bootloader answers nothing until EN is pulsed."""
    lines: list[tuple[bool, bool]] = []

    class StuckBench(Bench):
        def transport(self):
            host_end = super().transport()
            ncp_end = self.ncp_end
            ncp_end.is_open = False  # silent

            def on_lines(dtr: bool, rts: bool) -> None:
                lines.append((dtr, rts))
                if (dtr, rts) == (False, False) and (False, True) in lines:
                    ncp_end.is_open = True  # EN released: the firmware boots

            host_end.on_lines = on_lines
            return host_end

    app, bench = await start_app(tmp_path, StuckBench(SimNcp()), connect_timeout=1.0)
    try:
        assert lines.count((False, True)) == 1
        assert app._baudrate == 921600  # no baud fallback for a stuck NCP
        assert app.state.network_info.pan_id == bench.sim.net.pan_id
    finally:
        await stop(app, bench)


async def test_silent_first_open_is_revived_by_reopening(tmp_path) -> None:
    """A link silent for one whole open recovers on the next open, no reset."""
    lines: list[tuple[bool, bool]] = []

    class OnceSilentBench(Bench):
        opens = 0

        def transport(self):
            host_end = super().transport()
            self.opens += 1
            if self.opens == 1:
                self.ncp_end.is_open = False
            host_end.on_lines = lambda dtr, rts: lines.append((dtr, rts))
            return host_end

    bench = OnceSilentBench(SimNcp())
    app, bench = await start_app(tmp_path, bench, connect_timeout=1.0)
    try:
        assert bench.opens == 2
        assert (False, True) not in lines  # no EN pulse
        assert app._baudrate == 921600
    finally:
        await stop(app, bench)
