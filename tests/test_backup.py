"""Backups through zigpy: export, restore, OCB migration, key-export lock."""

from __future__ import annotations

import zigpy.backups
import zigpy.types as t

from zigpy_zrhp import messages as m
from zigpy_zrhp.sim.ncp import SimDevice, SimNcp
from zigpy_zrhp.types import FC_STRIDE, NcpCaps

from .app_bench import Bench, start_app, stop, wait_for
from .conftest import load_vector

DEV = bytes.fromhex("0c0b0afeff142e84")


async def test_backup_contents(tmp_path) -> None:
    app, bench = await start_app(tmp_path)
    sim = bench.sim
    try:
        sim.join(SimDevice(ieee=DEV, nwk=0x2222))
        await wait_for(lambda: t.EUI64(DEV) in app.devices, 5)
        backup = await app.backups.create_backup(load_devices=True)
        ni = backup.network_info
        assert backup.is_complete()
        assert ni.network_key.tx_counter == sim.nwk_limit  # durable limit
        assert t.EUI64(DEV) in ni.children
        assert ni.nwk_addresses[t.EUI64(DEV)] == 0x2222
        (key,) = ni.key_table
        assert key.partner_ieee == t.EUI64(DEV)
        assert key.key == t.KeyData(sim.devices[DEV].key)
        assert key.tx_counter == sim.aps_limit  # global APS limit
        assert ni.tc_link_key.tx_counter == sim.aps_limit
        zrs = ni.stack_specific["zigbee_rs"]
        assert zrs["table_epoch"] == sim.table_epoch
        assert zrs["frame_counter_stride"] == FC_STRIDE
        assert ni.metadata["zigbee_rs"]["fw"] == "0.1.0-sim"
        ocb = backup.as_open_coordinator_json()
        assert ocb["stack_specific"]["zigbee_rs"]["nwk_frame_counter_limit"] == sim.nwk_limit
    finally:
        await stop(app, bench)


async def test_backup_restore_to_another_ncp(tmp_path) -> None:
    app, bench = await start_app(tmp_path / "a")
    sim = bench.sim
    try:
        sim.join(SimDevice(ieee=DEV, nwk=0x2222))
        await wait_for(lambda: t.EUI64(DEV) in app.devices, 5)
        backup = await app.backups.create_backup(load_devices=True)
        dev_key = sim.devices[DEV].key
    finally:
        await stop(app, bench)

    # A fresh NCP with another factory IEEE (migration to new hardware).
    (tmp_path / "b").mkdir()
    sim2 = SimNcp(ieee=bytes.fromhex("1112131415161718"))
    bench2 = Bench(sim2)
    try:
        from .app_bench import BenchApp, make_config

        class App(BenchApp):
            pass

        App.bench = bench2
        app2 = App(make_config(tmp_path / "b"))
        await app2._load_db()
        await app2.connect()
        await app2.backups.restore_backup(backup)
        assert sim2.ieee == sim.ieee  # IEEE override (IEEE_REWRITABLE)
        assert sim2.net.pan_id == sim.net.pan_id and sim2.net.key == sim.net.key
        assert sim2.devices[DEV].key == dev_key
        # zigpy added 10 000 to the NWK counter, the library 10 000 to APS.
        assert sim2.last_restore.nwk_fc_start == backup.network_info.network_key.tx_counter + 10_000
        assert sim2.last_restore.aps_fc_start == backup.network_info.tc_link_key.tx_counter + 10_000
        # The host stored the keys before COMMIT (9.4 rule 3).
        row = await app2._store.get_link_key(ieee=DEV)
        assert row.key == dev_key
        await app2.initialize()
        new = app2.backups.from_network_state()
        assert new.is_compatible_with(backup)
        await app2.shutdown()
    finally:
        await sim2.stop()


async def test_restore_while_running_wipes_first(tmp_path) -> None:
    app, bench = await start_app(tmp_path)
    sim = bench.sim
    try:
        backup = await app.backups.create_backup(load_devices=True)
        n = len(sim.requests)
        await app.backups.restore_backup(backup)
        ids = [mid for mid, _ in sim.requests[n:]]
        assert ids.index(m.Id.NWK_LEAVE_RESET) < ids.index(m.Id.BKP_RESTORE_BEGIN)
        leave = m.decode_message(sim.requests[n + ids.index(m.Id.NWK_LEAVE_RESET)][1])
        assert leave.flags == 0x03  # keep the IEEE override and the endpoints
        assert app.backups.most_recent_backup().supersedes(backup)
    finally:
        await stop(app, bench)


async def test_ezsp_ocb_migration(tmp_path) -> None:
    """An EZSP-era OCB (hashed TCLK) restored through zigpy and exported again."""
    rt = load_vector("ocb_roundtrip.json")
    src = zigpy.backups.NetworkBackup.from_dict(rt["input_ocb"])
    sim = SimNcp(ieee=bytes.fromhex("1112131415161718"))
    bench = Bench(sim)
    from .app_bench import BenchApp, make_config

    class App(BenchApp):
        pass

    App.bench = bench
    app = App(make_config(tmp_path))
    await app._load_db()
    try:
        await app.connect()
        await app.backups.restore_backup(src)
        assert sim.net.hashed_seed == bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
        assert sim.net.tclk_flags & 0x01
        # zigpy adds 10 000 to the NWK counter, the library 10 000 to APS.
        assert sim.last_restore.nwk_fc_start == 2_000_000 + 10_000
        assert sim.last_restore.aps_fc_start == 3_000 + 10_000
        # NWK_INIT then raises them to the checkpoint-log floors (8.4).
        assert sim.nwk_current >= 2_010_000 and sim.aps_current >= 13_000
        assert sim.ieee == bytes.fromhex("3c2b1afeffb1b3f4")
        out = await app.backups.create_backup(load_devices=True)
        assert out.is_compatible_with(src)
        ocb = out.as_open_coordinator_json()
        assert ocb["stack_specific"]["ezsp"]["hashed_tclk"] == "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
        assert {d["ieee_address"] for d in ocb["devices"]} >= {
            "0017880102a1b2c3",
            "842e14fffe0a0b0c",
        }
        assert all(
            d["link_key"]["tx_counter"] == sim.aps_limit for d in ocb["devices"] if "link_key" in d
        )
        assert ocb["metadata"]["internal"]["ezspVersion"] == 13  # passed through
    finally:
        await app.shutdown()
        await sim.stop()


async def test_key_export_lock_makes_backup_incomplete(tmp_path) -> None:
    app, bench = await start_app(tmp_path, lock_key_export_after_backup=True)
    sim = bench.sim
    try:
        # Formation already took a (complete) backup, which locked the export.
        first = app.backups.most_recent_backup()
        assert first is not None and first.is_complete()
        await wait_for(lambda: sim.key_export_locked, 3)
        second = await app.backups.create_backup(load_devices=True)
        assert not second.is_complete()
        assert app.backups.most_recent_backup() is first
        # The lock is re-applied after an NCP reboot (resume replay).
        await sim.reboot()
        await wait_for(lambda: app._resumed.is_set() and sim.key_export_locked, 5)
    finally:
        await stop(app, bench)


async def test_no_ieee_change_without_capability(tmp_path) -> None:
    import zigpy.exceptions

    app, bench = await start_app(tmp_path)
    try:
        backup = await app.backups.create_backup(load_devices=True)
    finally:
        await stop(app, bench)
    sim = SimNcp(
        ieee=bytes.fromhex("2122232425262728"),
        caps=int(NcpCaps.BACKUP_RESTORE | NcpCaps.KEY_EXPORT),
    )
    bench2 = Bench(sim)
    from .app_bench import BenchApp, make_config

    class App(BenchApp):
        pass

    App.bench = bench2
    (tmp_path / "x").mkdir()
    app2 = App(make_config(tmp_path / "x"))
    await app2._load_db()
    try:
        await app2.connect()
        try:
            await app2.backups.restore_backup(backup)
        except zigpy.exceptions.CannotWriteNetworkSettings:
            pass
        else:
            raise AssertionError("expected CannotWriteNetworkSettings")
    finally:
        await app2.shutdown()
        await sim.stop()
