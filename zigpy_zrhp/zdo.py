"""ZDO requests to the coordinator itself, answered on the host (spec 7.4).

ZRHP has no ZDO loopback: the NCP refuses profile-0 frames to its own
address. zigpy still sends them (interview of the coordinator, topology
scans, energy scans, permit join), so the library synthesizes the responses
from ``NWK_*`` / ``DIAG_*`` commands and the registered endpoints.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import zigpy.types as t
import zigpy.zdo.types as zdo_t

from . import messages as m
from .types import Status

if TYPE_CHECKING:
    from .zigbee.application import ControllerApplication

LOGGER = logging.getLogger(__name__)

NOT_SUPPORTED = zdo_t.Status.NOT_SUPPORTED

#: Coordinator node descriptor (2.4 GHz, mains, TC, receiver on).
NODE_DESCRIPTOR = zdo_t.NodeDescriptor(
    logical_type=zdo_t.LogicalType.Coordinator,
    complex_descriptor_available=0,
    user_descriptor_available=0,
    reserved=0,
    aps_flags=0,
    frequency_band=zdo_t.NodeDescriptor.FrequencyBand.Freq2400MHz,
    mac_capability_flags=(
        zdo_t.NodeDescriptor.MACCapabilityFlags.AlternatePanCoordinator
        | zdo_t.NodeDescriptor.MACCapabilityFlags.FullFunctionDevice
        | zdo_t.NodeDescriptor.MACCapabilityFlags.MainsPowered
        | zdo_t.NodeDescriptor.MACCapabilityFlags.RxOnWhenIdle
        | zdo_t.NodeDescriptor.MACCapabilityFlags.AllocateAddress
    ),
    manufacturer_code=0x0000,
    maximum_buffer_size=82,
    maximum_incoming_transfer_size=128,
    server_mask=0x2C41,  # stack compliance revision 22, primary TC, network manager
    maximum_outgoing_transfer_size=128,
    descriptor_capability_field=zdo_t.NodeDescriptor.DescriptorCapability.NONE,
)


def _rsp(cmd: zdo_t.ZDOCmd, tsn: int, *args) -> bytes:
    _, types = zdo_t.CLUSTERS[cmd]
    return t.uint8_t(tsn).serialize() + t.serialize(args, types)


class LocalZdo:
    """Answers ZDO requests addressed to the coordinator."""

    def __init__(self, app: ControllerApplication) -> None:
        self.app = app

    def is_local(self, packet: t.ZigbeePacket) -> bool:
        if packet.profile_id != 0 or packet.dst is None:
            return False
        node = self.app.state.node_info
        dst = packet.dst
        if dst.addr_mode == t.AddrMode.NWK:
            return dst.address == node.nwk
        if dst.addr_mode == t.AddrMode.IEEE:
            return dst.address == node.ieee
        return False

    async def handle(self, packet: t.ZigbeePacket) -> bytes | None:
        """Return the ASDU of the response (``None`` sends nothing)."""
        data = packet.data.serialize()
        tsn, data = t.uint8_t.deserialize(data)
        cmd = zdo_t.ZDOCmd(packet.cluster_id)
        names, types = zdo_t.CLUSTERS.get(cmd, ((), ()))
        try:
            args, _ = t.deserialize(data, types)
        except (ValueError, KeyError):
            args = []
        handler = getattr(self, f"_{cmd.name}", None) if cmd.name else None
        if handler is None:
            if cmd & 0x8000:
                return None
            LOGGER.debug("Unsupported local ZDO request %s", cmd)
            return t.uint8_t(tsn).serialize() + NOT_SUPPORTED.serialize()
        return await handler(tsn, *args)

    @property
    def nwk(self) -> t.NWK:
        return self.app.state.node_info.nwk

    async def _Node_Desc_req(self, tsn, nwk):
        desc = NODE_DESCRIPTOR.replace(manufacturer_code=self.app.manufacturer_code)
        return _rsp(zdo_t.ZDOCmd.Node_Desc_rsp, tsn, zdo_t.Status.SUCCESS, self.nwk, desc)

    async def _Active_EP_req(self, tsn, nwk):
        eps = sorted({*self.app.host_endpoints, 242})
        return _rsp(
            zdo_t.ZDOCmd.Active_EP_rsp,
            tsn,
            zdo_t.Status.SUCCESS,
            self.nwk,
            [t.uint8_t(e) for e in eps],
        )

    async def _Simple_Desc_req(self, tsn, nwk, ep):
        desc = self.app.host_endpoints.get(ep)
        if desc is None and ep == 242:
            desc = self.app.gp_endpoint_descriptor()
        if desc is None:
            return _rsp(zdo_t.ZDOCmd.Simple_Desc_rsp, tsn, zdo_t.Status.NOT_ACTIVE, self.nwk, None)
        sd = zdo_t.SizePrefixedSimpleDescriptor(
            endpoint=desc.endpoint,
            profile=desc.profile,
            device_type=desc.device_type,
            device_version=desc.device_version,
            input_clusters=list(desc.input_clusters),
            output_clusters=list(desc.output_clusters),
        )
        return _rsp(zdo_t.ZDOCmd.Simple_Desc_rsp, tsn, zdo_t.Status.SUCCESS, self.nwk, sd)

    async def _addr_rsp(self, cmd, tsn):
        node = self.app.state.node_info
        return _rsp(cmd, tsn, zdo_t.Status.SUCCESS, node.ieee, node.nwk, 0, 0, [])

    async def _NWK_addr_req(self, tsn, ieee, *rest):
        return await self._addr_rsp(zdo_t.ZDOCmd.NWK_addr_rsp, tsn)

    async def _IEEE_addr_req(self, tsn, nwk, *rest):
        return await self._addr_rsp(zdo_t.ZDOCmd.IEEE_addr_rsp, tsn)

    async def _diag(self, req):
        status, rsp = await self.app._api.request(
            req, allow=(Status.SUCCESS, Status.UNSUPPORTED_COMMAND)
        )
        return rsp if status == Status.SUCCESS else None

    async def _Mgmt_Lqi_req(self, tsn, start):
        rsp = await self._diag(m.DiagGetNeighborsReq(start=start))
        if rsp is None:
            return t.uint8_t(tsn).serialize() + NOT_SUPPORTED.serialize()
        epid = self.app.state.network_info.extended_pan_id
        entries = []
        for n in rsp.entries:
            entries.append(
                zdo_t.Neighbor(
                    extended_pan_id=epid,
                    ieee=t.EUI64(n.ieee),
                    nwk=t.NWK(n.nwk),
                    device_type=zdo_t.Neighbor.DeviceType(min(n.device_type, 3)),
                    rx_on_when_idle=zdo_t.Neighbor.RxOnWhenIdle(min(n.rx_on, 2)),
                    relationship=zdo_t.Neighbor.Relationship(min(n.relationship, 4)),
                    reserved1=0,
                    permit_joining=zdo_t.Neighbor.PermitJoins.Unknown,
                    reserved2=0,
                    depth=1 if n.relationship in (1, 4) else 0xFF,
                    lqi=n.lqi,
                )
            )
        neighbors = zdo_t.Neighbors(Entries=rsp.total, StartIndex=start, NeighborTableList=entries)
        return _rsp(zdo_t.ZDOCmd.Mgmt_Lqi_rsp, tsn, zdo_t.Status.SUCCESS, neighbors)

    async def _Mgmt_Rtg_req(self, tsn, start):
        rsp = await self._diag(m.DiagGetRoutesReq(start=start))
        if rsp is None:
            return t.uint8_t(tsn).serialize() + NOT_SUPPORTED.serialize()
        routes = [
            zdo_t.Route(
                DstNWK=t.NWK(r.dst),
                RouteStatus=zdo_t.RouteStatus(r.status & 0x07),
                MemoryConstrained=(r.flags >> 0) & 1,
                ManyToOne=(r.flags >> 1) & 1,
                RouteRecordRequired=(r.flags >> 2) & 1,
                Reserved=0,
                NextHop=t.NWK(r.next_hop),
            )
            for r in rsp.entries
        ]
        table = zdo_t.Routes(Entries=rsp.total, StartIndex=start, RoutingTableList=routes)
        return _rsp(zdo_t.ZDOCmd.Mgmt_Rtg_rsp, tsn, zdo_t.Status.SUCCESS, table)

    async def _Mgmt_Bind_req(self, tsn, start):
        return _rsp(zdo_t.ZDOCmd.Mgmt_Bind_rsp, tsn, zdo_t.Status.SUCCESS, 0, start, [])

    async def _Mgmt_Permit_Joining_req(self, tsn, duration, tc_significance):
        await self.app.permit_ncp(duration)
        return _rsp(zdo_t.ZDOCmd.Mgmt_Permit_Joining_rsp, tsn, zdo_t.Status.SUCCESS)

    async def _Mgmt_NWK_Update_req(self, tsn, update):
        if update.ScanDuration == zdo_t.NwkUpdate.CHANNEL_CHANGE_REQ:
            channel = list(update.ScanChannels)[0]
            await self.app._move_network_to_channel(channel, update.nwkUpdateId)
            return None  # no response to a channel change request
        if update.ScanDuration > 5:
            return t.uint8_t(tsn).serialize() + NOT_SUPPORTED.serialize()
        energy = await self.app.energy_scan(
            channels=update.ScanChannels, duration_exp=update.ScanDuration, count=update.ScanCount
        )
        return _rsp(
            zdo_t.ZDOCmd.Mgmt_NWK_Update_rsp,
            tsn,
            zdo_t.Status.SUCCESS,
            t.Channels.from_channel_list(energy.keys()),
            0,
            0,
            [t.uint8_t(round(v)) for v in energy.values()],
        )

    async def _Mgmt_Leave_req(self, tsn, *args):
        return t.uint8_t(tsn).serialize() + NOT_SUPPORTED.serialize()
