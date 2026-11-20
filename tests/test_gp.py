"""Green Power shadow sink (spec 7.11, steps 1-7) against stock zigpy and the hook."""

from __future__ import annotations

import struct

import pytest
from zigpy.device import GreenPowerDevice
import zigpy.types as t
from zigpy.zgp.types import ApplicationID, SecurityKeyType, SecurityLevel, SrcID
from zigpy.zgp.util import synthetic_ieee

from zigpy_zrhp.gp import zigpy_has_radio_sink_hook
from zigpy_zrhp.records import GpdId, GpSinkRecord

from .app_bench import start_app, stop, wait_for

HOOK = zigpy_has_radio_sink_hook()
SRC_PLAIN = 0x0155AA01
SRC_SECURE = 0x293C9879
KEY = bytes.fromhex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf")

#: Level-0 GPD (FlowerX GP / BGT1 GP style): OnOff switch, MAC seq capable.
COMM_PLAIN = bytes([0x02, 0x01])
#: Level-3 GPD with an individual key in the clear and an outgoing counter.
COMM_SECURE = bytes([0x02, 0x81, 0xB3]) + KEY + struct.pack("<I", 4440)


async def _commission(app, sim, src, payload, **kw):
    await app.permit(60)
    rec = sim.gp_commission(src, payload, **kw)
    assert rec is not None
    ieee = synthetic_ieee(src)
    await wait_for(lambda: ieee in app.devices, 5)
    return app.devices[ieee]


def _sink_frames_on_air(sim) -> list:
    return [
        r
        for r in sim.sent_aps
        if (r.cluster == 0x0021 and r.src_ep == 242) or (r.profile == 0 and r.cluster == 0x0013)
    ]


async def test_level0_gpd_commissions_once(tmp_path) -> None:
    app, bench = await start_app(tmp_path)
    sim = bench.sim
    try:
        dev = await _commission(app, sim, SRC_PLAIN, COMM_PLAIN, frame_counter=0, mac_seq=7)
        assert isinstance(dev, GreenPowerDevice)
        assert dev.security_level == SecurityLevel.NoSecurity
        assert dev.security_key_type == SecurityKeyType.NoKey
        # One pairing on air: the NCP's. zigpy's own sink frames never left the host.
        assert _sink_frames_on_air(sim) == []
        assert sim.conflicts == []
        kinds = {k for k, _ in app._gp.swallowed}
        if not HOOK:
            assert {"GP Proxy Commissioning Mode", "GP Pairing", "GPD alias Device_annce"} <= kinds
        # Operational frames feed zigpy.
        sim.gp_frame(SRC_PLAIN, 0x22, result=1, frame_counter=8)
        await wait_for(lambda: dev.frame_counter == 8, 3)
        sim.gp_frame(SRC_PLAIN, 0x22, result=1, frame_counter=9)
        await wait_for(lambda: dev.frame_counter == 9, 3)
        # The sidecar mirrors the NCP sink entry.
        shadow = await app._store.gp_all()
        assert GpdId.pack(GpdId.srcid(SRC_PLAIN)) in shadow
    finally:
        await stop(app, bench)


async def test_secured_gpd_and_counter_checks(tmp_path) -> None:
    app, bench = await start_app(tmp_path)
    sim = bench.sim
    try:
        dev = await _commission(
            app,
            sim,
            SRC_SECURE,
            COMM_SECURE,
            security_level=3,
            key_type=4,
            key=KEY,
            frame_counter=4440,
        )
        assert dev.security_level == SecurityLevel.Encrypted
        assert dev.security_key == t.KeyData(KEY)
        assert dev.frame_counter == 4440
        sim.gp_frame(SRC_SECURE, 0x22, result=1, frame_counter=4441, security_level=3, key_type=4)
        await wait_for(lambda: dev.frame_counter == 4441, 3)
        # The NCP de-duplicates; a replay that slipped through is still dropped by zigpy.
        sim.gp_frame(SRC_SECURE, 0x22, result=1, frame_counter=4441, security_level=3, key_type=4)
        sim.gp_frame(SRC_SECURE, 0x20, result=1, frame_counter=4442, security_level=3, key_type=4)
        await wait_for(lambda: dev.frame_counter == 4442, 3)
    finally:
        await stop(app, bench)


async def test_remove_gpd_uses_gp_sink_remove(tmp_path) -> None:
    app, bench = await start_app(tmp_path)
    sim = bench.sim
    try:
        dev = await _commission(app, sim, SRC_PLAIN, COMM_PLAIN)
        assert GpdId.srcid(SRC_PLAIN) in sim.gp_sink
        await app.remove(dev.ieee)
        await wait_for(lambda: GpdId.srcid(SRC_PLAIN) not in sim.gp_sink, 3)
        assert _sink_frames_on_air(sim) == []
        assert sim.conflicts == []
    finally:
        await stop(app, bench)


async def test_existing_zigpy_gpds_are_imported(tmp_path) -> None:
    """GPDs from an EZSP era are pushed into the NCP sink without a pairing."""
    app, bench = await start_app(tmp_path)
    sim = bench.sim
    try:
        dev = GreenPowerDevice(app, application_id=ApplicationID.SrcID, src_id=SrcID(0x11223344))
        from zigpy.zgp.types import DeviceID

        dev.device_id = DeviceID.OnOffSwitch
        dev.security_level = SecurityLevel.FullFrameCounterAndMIC
        dev.security_key_type = SecurityKeyType.IndividualKey
        dev.security_key = t.KeyData(KEY)
        dev.frame_counter = t.uint32_t(77)
        app.listener_event("device_joined", dev)
        app.device_initialized(dev)
        await app._gp.reconcile()
        rec = sim.gp_sink[GpdId.srcid(0x11223344)]
        assert (rec.security_level, rec.key_type, rec.key, rec.frame_counter) == (2, 4, KEY, 77)
        assert rec.group == 0x0B84 and rec.communication_mode == 2
        assert _sink_frames_on_air(sim) == []
    finally:
        await stop(app, bench)


async def test_ncp_only_gpd_is_adopted_on_start(tmp_path) -> None:
    app, bench = await start_app(tmp_path)
    sim = bench.sim
    await app.shutdown()
    # Commissioned by the NCP while no host was connected.
    sim.gp_sink[GpdId.srcid(0x0A0B0C0D)] = GpSinkRecord(
        gpd_id=GpdId.srcid(0x0A0B0C0D), device_id=0x02, group=0x0B84, flags=0x01, frame_counter=3
    )
    await sim.reboot()
    app2, _ = await start_app(tmp_path, bench, auto_form=False)
    try:
        ieee = synthetic_ieee(0x0A0B0C0D)
        await wait_for(lambda: ieee in app2.devices, 3)
        assert isinstance(app2.devices[ieee], GreenPowerDevice)
    finally:
        await stop(app2, bench)


async def test_gp_survives_ncp_reboot(tmp_path) -> None:
    app, bench = await start_app(tmp_path)
    sim = bench.sim
    try:
        dev = await _commission(app, sim, SRC_PLAIN, COMM_PLAIN, mac_seq=1)
        await sim.reboot()
        await wait_for(lambda: app._resumed.is_set() and sim.gp_config is not None, 5)
        assert sim.gp_config.security_level == 0
        sim.gp_frame(SRC_PLAIN, 0x22, result=1, frame_counter=2)
        await wait_for(lambda: dev.frame_counter == 2, 3)
    finally:
        await stop(app, bench)


@pytest.mark.skipif(not HOOK, reason="needs the faronov/zigpy sink-on-radio hook")
async def test_hook_delegates_and_transmits_nothing(tmp_path) -> None:
    app, bench = await start_app(tmp_path)
    sim = bench.sim
    try:
        await _commission(app, sim, SRC_PLAIN, COMM_PLAIN)
        assert app._gp.swallowed == []  # zigpy sent nothing itself
        enters = [r for mid, r in sim.requests if mid == 0x0A03]
        assert len(enters) >= 1
    finally:
        await stop(app, bench)
