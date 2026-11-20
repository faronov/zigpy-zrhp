"""ControllerApplication against the simulated NCP: form, join, data, ZDO."""

from __future__ import annotations

import asyncio

import zigpy.exceptions
import zigpy.types as t
import zigpy.zdo.types as zdo_t

from zigpy_zrhp import messages as m
from zigpy_zrhp.sim.ncp import SimDevice, SimEndpoint, SimNcp

from .app_bench import Bench, start_app, stop, wait_for

DEV_IEEE = bytes.fromhex("0c0b0afeff142e84")


async def test_form_network_from_scratch(tmp_path) -> None:
    app, bench = await start_app(tmp_path)
    try:
        sim = bench.sim
        assert sim.formed and sim.running
        ni = app.state.network_info
        assert ni.pan_id == sim.net.pan_id
        assert ni.extended_pan_id == t.ExtendedPanId(sim.net.ext_pan_id)
        assert ni.channel in (11, 15, 20, 25)
        assert ni.network_key.key == t.KeyData(sim.net.key)
        assert ni.tc_link_key.key == t.KeyData(b"ZigBeeAlliance09")
        assert app.state.node_info.ieee == t.EUI64(sim.ieee)
        assert app.state.node_info.nwk == 0x0000
        # Host endpoints registered (GP endpoint 242 stays the NCP's).
        assert sorted(sim.endpoints) == [1, 2]
        # GP sink configured with the zigpy profile (decision N1).
        assert sim.gp_config.mode == 1
        assert sim.gp_config.security_level == 0
        assert sim.gp_config.group == 0x0B84
        # The coordinator interview ran locally: no ZDO to the NCP's own address.
        assert app._device.is_initialized
        assert all(not (r.profile == 0 and r.dst == 0) for r in sim.sent_aps)
        assert app._device.manufacturer == "zigbee-rs"
        # The startup permit(0) closed joining through the NCP.
        assert sim.permit_log[-1] == (0, 0xFFFC)
        # A backup is complete.
        backup = await app.backups.create_backup(load_devices=True)
        assert backup.is_complete()
    finally:
        await stop(app, bench)


async def test_restart_resumes_existing_network(tmp_path) -> None:
    app, bench = await start_app(tmp_path)
    pan = bench.sim.net.pan_id
    await app.shutdown()
    # Same NCP, new host process.
    await bench.sim.reboot()
    app2, _ = await start_app(tmp_path, bench, auto_form=False)
    try:
        assert app2.state.network_info.pan_id == pan
        assert bench.sim.running
        # NWK_INIT carried the checkpoint-log floors.
        inits = [msg for mid, msg in bench.sim.requests if mid == m.Id.NWK_INIT]
        req = m.decode_message(inits[-1])
        assert req.nwk_fc_floor > 0 and req.aps_fc_floor > 0
    finally:
        await stop(app2, bench)


async def test_not_formed_raises_without_auto_form(tmp_path) -> None:
    try:
        await start_app(tmp_path, auto_form=False)
    except zigpy.exceptions.NetworkNotFormed:
        pass
    else:
        raise AssertionError("expected NetworkNotFormed")


async def test_device_join_interview_and_data(tmp_path) -> None:
    app, bench = await start_app(tmp_path)
    sim = bench.sim
    try:
        await app.permit(60)
        assert sim.permit_log[-1] == (60, 0xFFFC)
        assert sim.gp_commissioning_until is not None  # GP window opened too
        dev = SimDevice(
            ieee=DEV_IEEE,
            nwk=0x4F21,
            model="SIM-LAMP",
            endpoints=[SimEndpoint(1, in_clusters=[0x0000, 0x0006, 0x0008])],
        )
        sim.join(dev)
        ieee = t.EUI64(DEV_IEEE)
        await wait_for(lambda: ieee in app.devices and app.devices[ieee].model is not None, 10)
        zdev = app.devices[ieee]
        assert zdev.model == "SIM-LAMP"
        assert zdev.manufacturer == "zigbee-rs"
        assert zdev.nwk == 0x4F21
        # Unicast with APS ACK.
        rsp = await zdev.endpoints[1].on_off.on()
        assert rsp[1] == 0  # default response SUCCESS
        req = sim.sent_aps[-1]
        assert req.dst_mode == m.AddrMode.NWK and req.dst == 0x4F21 and req.cluster == 0x0006
        # An attribute report reaches zigpy.
        on_off = zdev.endpoints[1].on_off
        sim.report(dev, 1, 0x0006, bytes([0x18, 0x42, 0x0A, 0x00, 0x00, 0x10, 0x01]))
        await wait_for(lambda: on_off.get("on_off") is not None, 3)
        assert on_off.get("on_off") is True or on_off.get("on_off") == 1
        assert zdev.lqi == dev.lqi and zdev.rssi == dev.rssi
        # Delivery failure surfaces as DeliveryError.
        dev.responsive = False
        try:
            await zdev.endpoints[1].on_off.off()
        except zigpy.exceptions.DeliveryError as e:
            assert e.status == 0xA7
        else:
            raise AssertionError("expected DeliveryError")
        # Leave.
        sim.leave(dev)
        await asyncio.sleep(0.05)
    finally:
        await stop(app, bench)


async def test_busy_is_retried(tmp_path) -> None:
    app, bench = await start_app(tmp_path)
    sim = bench.sim
    try:
        sim.join(SimDevice(ieee=DEV_IEEE, nwk=0x1234))
        ieee = t.EUI64(DEV_IEEE)
        await wait_for(lambda: ieee in app.devices and app.devices[ieee].model is not None, 10)
        sim.busy_next = 3
        await app.devices[ieee].endpoints[1].on_off.toggle()
        assert sim.busy_next == 0
    finally:
        await stop(app, bench)


async def test_local_zdo_and_topology(tmp_path) -> None:
    app, bench = await start_app(tmp_path)
    sim = bench.sim
    try:
        sim.add_device(SimDevice(ieee=DEV_IEEE, nwk=0x1234))
        status, neighbors = await app._device.zdo.Mgmt_Lqi_req(0)
        assert status == zdo_t.Status.SUCCESS
        assert neighbors.Entries == 1
        assert neighbors.NeighborTableList[0].ieee == t.EUI64(DEV_IEEE)
        status, nwk, desc = await app._device.zdo.Node_Desc_req(0x0000)
        assert desc.logical_type == zdo_t.LogicalType.Coordinator
        energy = await app.energy_scan(t.Channels.from_channel_list([11, 15]), 2, 1)
        assert set(energy) == {11, 15}
        # Nothing of this went to the NCP as ZDO.
        assert all(r.profile != 0 or r.dst not in (0, sim.ieee) for r in sim.sent_aps)
    finally:
        await stop(app, bench)


async def test_tbl_writeback_and_lookup(tmp_path) -> None:
    app, bench = await start_app(tmp_path)
    sim = bench.sim
    try:
        from zigpy_zrhp.records import DeviceRecord, LinkBlock
        from zigpy_zrhp.types import Endpoint, Kind

        rec = DeviceRecord(
            ieee=DEV_IEEE,
            nwk=0x4F21,
            flags=0x08,
            link=LinkBlock(
                key=bytes(range(16)), key_seq=0, attrs=2, origin=2, tx_counter=0, rx_floor=3
            ),
        )
        responses = []
        orig = app._api._on_data

        def spy(ep, payload):
            for msg in m.parse_batch(payload):
                if msg.kind is Kind.RESPONSE and msg.msg_id in (
                    m.Id.TBL_WRITEBACK,
                    m.Id.TBL_LOOKUP,
                ):
                    responses.append(msg)
            orig(ep, payload)

        sim.driver.send(
            Endpoint.TABLES,
            m.Message(
                Kind.REQUEST,
                m.Id.TBL_WRITEBACK,
                7,
                m.TblWritebackReq(table=5, reason=1, rev=9, record=rec).serialize(),
            ).serialize(),
        )
        # Responses travel NCP-ward; capture them at the NCP.
        sim.requests.clear()
        ncp_seen = []
        old = sim._on_link_event

        def ncp_spy(ev):
            from zigpy_zrhp.link import Data

            if isinstance(ev, Data):
                for msg in m.parse_batch(ev.payload):
                    if msg.kind is Kind.RESPONSE:
                        ncp_seen.append(msg)
            old(ev)

        sim.driver._on_event = ncp_spy
        await wait_for(lambda: ncp_seen, 3)
        assert ncp_seen[0].payload == b"\x00"
        row = await app._store.get_link_key(ieee=DEV_IEEE)
        assert row.key == bytes(range(16)) and row.rev == 9 and row.rx_floor == 3
        assert await app._store.meta("host_max_rev") == 9
        sim.driver.send(
            Endpoint.TABLES,
            m.Message(
                Kind.REQUEST,
                m.Id.TBL_LOOKUP,
                8,
                m.TblLookupReq(table=5, key=m.TableKey(2, 0x4F21)).serialize(),
            ).serialize(),
        )
        await wait_for(lambda: len(ncp_seen) >= 2, 3)
        status, body = m.decode_response(m.Id.TBL_LOOKUP, ncp_seen[1].payload)
        assert status == 0 and body.rev == 9 and body.record.link.key == bytes(range(16))
    finally:
        await stop(app, bench)


async def test_uart_fallback_rate(tmp_path) -> None:
    """No session at 921 600 -> the library retries at 460 800 without flow control."""
    bench = Bench(SimNcp())
    calls = []

    class App(__import__("tests.app_bench", fromlist=["BenchApp"]).BenchApp):
        def _create_transport(self, baudrate, flow):
            calls.append((baudrate, flow))
            tr = bench.transport()
            if baudrate == 921600:
                tr.mangle = lambda data: b"\x55" * len(data)  # wrong rate: garbage
                bench.ncp_end.mangle = tr.mangle
            return tr

    from .app_bench import make_config

    app = await App.new(make_config(tmp_path, connect_timeout=0.5), auto_form=True)
    try:
        assert calls[0] == (921600, None)
        assert calls[-1] == (460800, None)
        assert app._baudrate == 460800
    finally:
        await stop(app, bench)
