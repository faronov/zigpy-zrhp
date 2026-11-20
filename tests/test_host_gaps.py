"""NCP behaviour from zigbee-rs ``ncp-host-gaps`` (spec 5.10, 7.x, 9.4, 9.5)."""

from __future__ import annotations

import asyncio

import pytest
import zigpy.types as t
import zigpy.zdo.types as zdo_t

from zigpy_zrhp import messages as m
from zigpy_zrhp.api import RESPONSE_BUDGET
from zigpy_zrhp.sim.ncp import SimNcp
from zigpy_zrhp.types import Status

from .app_bench import Bench, start_app, stop, wait_for

DEV = t.EUI64.convert("00:0d:6f:ff:fe:0a:90:69")
# A Zigbee example install code with its CRC and the key it derives.
INSTALL_CODE = bytes.fromhex("83FED3407A939723A5C639B26916D505C3B5")
INSTALL_KEY = bytes.fromhex("66B6900981E1EE3CA4206B6B861C02BB")


async def test_response_budget_follows_capacity_19(tmp_path) -> None:
    app, bench = await start_app(tmp_path, Bench(SimNcp(response_budget=384)))
    try:
        assert app.api.response_budget() == 384
        assert app._export_chunk() == 368
        backup = await app.backups.create_backup(load_devices=True)
        assert backup.is_complete()
    finally:
        await stop(app, bench)


async def test_response_budget_without_capacity_19(tmp_path) -> None:
    app, bench = await start_app(tmp_path, Bench(SimNcp(legacy=True)))
    try:
        assert app.api.response_budget() == RESPONSE_BUDGET
    finally:
        await stop(app, bench)


async def test_busy_is_retried_on_any_request(tmp_path) -> None:
    app, bench = await start_app(tmp_path)
    sim = bench.sim
    busy = {"n": 3}

    def on_request(msg):
        if msg.msg_id == m.Id.SYS_GET_STATUS and busy["n"]:
            busy["n"] -= 1
            return bytes([Status.BUSY])
        return None

    try:
        sim.on_request = on_request
        status, _ = await app.api.request(m.SysGetStatusReq())
        assert status == Status.SUCCESS
        assert busy["n"] == 0
        assert app.api.counters["busy_retries"] == 3
        # A request that stays BUSY ends with BUSY within its timeout.
        busy["n"] = 10_000
        with pytest.raises(Exception, match="BUSY"):
            await app.api.request(m.SysGetStatusReq(), timeout=0.3)
    finally:
        sim.on_request = None
        await stop(app, bench)


async def test_reconcile_compares_stored_identity_before_nwk_init(tmp_path) -> None:
    """Z11: NWK_GET_INFO is valid in state 1, so nothing starts before the check."""
    app, bench = await start_app(tmp_path)
    sim = bench.sim
    try:
        n = len(sim.requests)
        await sim.reboot(reason=3)
        await wait_for(lambda: sim.running and app._resumed.is_set(), 10)
        ids = [mid for mid, _ in sim.requests[n:]]
        assert ids.index(m.Id.NWK_GET_INFO) < ids.index(m.Id.NWK_INIT)
    finally:
        await stop(app, bench)


async def test_reconcile_refuses_a_different_stored_network(tmp_path) -> None:
    app, bench = await start_app(tmp_path)
    sim = bench.sim
    lost: list[Exception] = []
    app.add_listener(type("L", (), {"connection_lost": lambda s, e: lost.append(e)})())
    try:
        await sim.reboot(reason=3, keep_link=False)
        sim.net.pan_id ^= 0x1111  # another network in NV
        n = len(sim.requests)
        await wait_for(lambda: lost, 10)
        # The foreign network was never started.
        assert m.Id.NWK_INIT not in [mid for mid, _ in sim.requests[n:]]
    finally:
        await stop(app, bench)


async def test_reconcile_on_legacy_ncp_starts_first(tmp_path) -> None:
    app, bench = await start_app(tmp_path, Bench(SimNcp(legacy=True)))
    sim = bench.sim
    try:
        n = len(sim.requests)
        await sim.reboot(reason=3)
        await wait_for(lambda: sim.running and app._resumed.is_set(), 10)
        ids = [mid for mid, _ in sim.requests[n:]]
        assert ids.index(m.Id.NWK_INIT) < len(ids) - 1 - ids[::-1].index(m.Id.NWK_GET_INFO)
        assert app.state.counters["zrhp"]["ncp_resumed"].value == 1
    finally:
        await stop(app, bench)


async def test_channel_change_waits_for_the_event(tmp_path) -> None:
    app, bench = await start_app(tmp_path, Bench(SimNcp(channel_change_delay=0.3)))
    sim = bench.sim
    try:
        old = app.state.network_info
        new_channel = 25 if old.channel != 25 else 20
        update_id = (old.nwk_update_id + 1) & 0xFF
        # A second change while the first is pending gets BUSY and is retried.
        await asyncio.gather(
            app._move_network_to_channel(new_channel, update_id),
            app._move_network_to_channel(new_channel, update_id),
        )
        assert app.state.network_info.channel == new_channel
        assert app.state.network_info.nwk_update_id == update_id
        assert sim.net.channel == new_channel
        assert app.api.counters["busy_retries"] >= 1
    finally:
        await stop(app, bench)


async def test_install_code_is_derived_by_the_ncp(tmp_path) -> None:
    app, bench = await start_app(tmp_path)
    sim = bench.sim
    try:
        await app.permit_with_key(DEV, INSTALL_CODE, time_s=30)
        assert sim.devices[DEV.serialize()].key == INSTALL_KEY
        row = await app._store.get_link_key(DEV.serialize())
        assert row is not None and row.key == INSTALL_KEY
        bad = INSTALL_CODE[:-1] + bytes([INSTALL_CODE[-1] ^ 1])
        with pytest.raises(ValueError):
            await app.permit_with_key(DEV, bad, time_s=30)
    finally:
        await stop(app, bench)


async def test_link_key_is_provisioned_and_kept_by_the_host(tmp_path) -> None:
    app, bench = await start_app(tmp_path)
    sim = bench.sim
    key = t.KeyData(bytes(range(16)))
    try:
        await app.permit_with_link_key(DEV, key, time_s=30)
        assert sim.devices[DEV.serialize()].key == bytes(range(16))
        row = await app._store.get_link_key(DEV.serialize())
        assert row is not None and row.key == bytes(range(16))
        assert sim.permit_log[-1][0] == 30
    finally:
        await stop(app, bench)


async def test_group_membership_including_gp_endpoint(tmp_path) -> None:
    app, bench = await start_app(tmp_path)
    sim = bench.sim
    try:
        await app._subscribe_to_multicast_group(t.Group(0x1234), 1)
        assert (0x1234, 1) in sim.groups
        status, _ = await app.api.request(m.NwkGroupMembershipReq(op=1, group=0x0B84, ep=242))
        assert status == Status.SUCCESS
        await app._unsubscribe_from_multicast_group(t.Group(0x1234), 1)
        assert (0x1234, 1) not in sim.groups
    finally:
        await stop(app, bench)


async def test_mgmt_lqi_maps_unauthenticated_child(tmp_path) -> None:
    app, bench = await start_app(tmp_path)
    sim = bench.sim
    entries = [
        m.Neighbor(
            ieee=bytes([i, 0, 0, 0, 0, 0, 0, 0x10]),
            nwk=0x1000 + i,
            device_type=2,
            rx_on=0,
            relationship=5 if i == 0 else 1,
            lqi=200,
            outgoing_cost=1,
            age=0,
        )
        for i in range(16)
    ]

    def on_request(msg):
        if msg.msg_id == m.Id.DIAG_GET_NEIGHBORS:
            return m.encode_response(m.DiagGetNeighborsRsp(total=20, entries=entries))
        return None

    try:
        sim.on_request = on_request
        status, neighbors = await app._device.zdo.Mgmt_Lqi_req(0)
        assert status == zdo_t.Status.SUCCESS
        assert neighbors.Entries == 20
        assert len(neighbors.NeighborTableList) == 16
        assert neighbors.NeighborTableList[0].relationship == zdo_t.Neighbor.Relationship.Child
    finally:
        sim.on_request = None
        await stop(app, bench)
