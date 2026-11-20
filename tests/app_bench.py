"""zigpy-level helpers: a ControllerApplication wired to the simulated NCP."""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
from typing import Any

import zigpy.config

from zigpy_zrhp.sim.ncp import SimNcp
from zigpy_zrhp.transport import MemoryTransport
from zigpy_zrhp.zigbee.application import ControllerApplication


@dataclasses.dataclass
class Bench:
    """One simulated NCP behind a (re-openable) in-memory port."""

    sim: SimNcp
    host_end: MemoryTransport | None = None
    ncp_end: MemoryTransport | None = None
    mangle: Any = None

    def transport(self) -> MemoryTransport:
        host_end, ncp_end = MemoryTransport.pair()
        self.host_end, self.ncp_end = host_end, ncp_end
        host_end.mangle = self.mangle
        ncp_end.mangle = self.mangle
        ncp_end.is_open = True
        if self.sim.driver is None:
            self.sim.attach(ncp_end)
        else:
            self.sim.driver.transport = ncp_end
            ncp_end.on_data = self.sim.driver._data_received
        return host_end


def make_config(tmp_path, **zrhp: Any) -> dict[str, Any]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    return {
        zigpy.config.CONF_DEVICE: {zigpy.config.CONF_DEVICE_PATH: "/dev/null"},
        zigpy.config.CONF_DATABASE: str(tmp_path / "zigbee.db"),
        zigpy.config.CONF_NWK_BACKUP_ENABLED: False,
        zigpy.config.CONF_TOPO_SCAN_ENABLED: False,
        zigpy.config.CONF_OTA: {zigpy.config.CONF_OTA_ENABLED: False},
        zigpy.config.CONF_WATCHDOG_ENABLED: False,
        "zrhp_config": {"connect_timeout": 2.0, "resume_budget": 3.0, **zrhp},
    }


class BenchApp(ControllerApplication):
    bench: Bench

    def _create_transport(self, baudrate, flow):  # type: ignore[override]
        return self.bench.transport()


async def start_app(tmp_path, bench: Bench | None = None, *, auto_form: bool = True, **zrhp: Any):
    bench = bench or Bench(SimNcp())

    class App(BenchApp):
        pass

    App.bench = bench
    app = App(make_config(tmp_path, **zrhp))
    await app._load_db()
    try:
        await app.startup(auto_form=auto_form)
    except BaseException:
        await app.shutdown()
        raise
    return app, bench


async def stop(app, bench: Bench) -> None:
    with contextlib.suppress(Exception):
        await app.shutdown()
    await bench.sim.stop()


async def wait_for(predicate, timeout: float = 5.0, interval: float = 0.01) -> None:
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(interval)
