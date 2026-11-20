"""The coordinator device object."""

from __future__ import annotations

import zigpy.device

from .. import __version__


class ZrhpCoordinator(zigpy.device.Device):
    """The zigbee-rs NCP as a zigpy device (its ZDO is answered on the host)."""

    @property
    def manufacturer(self) -> str:
        return "zigbee-rs"

    @property
    def model(self) -> str:
        app = self._application
        session = getattr(getattr(app, "_api", None), "session", None)
        fw = session.fw_version if session is not None else "?"
        product = getattr(app, "_product", None) or "ZRHP NCP"
        return f"{product} ({fw}, zigpy-zrhp {__version__})"
