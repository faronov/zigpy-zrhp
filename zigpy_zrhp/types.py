"""Shared protocol enums: link endpoints, message kinds, status codes, capabilities."""

from __future__ import annotations

import enum


class Endpoint(enum.IntEnum):
    """Link endpoints (spec 5.10). Not Zigbee endpoints."""

    LINK = 0
    SYSTEM = 1
    ZIGBEE = 2
    TABLES = 3
    BULK = 4
    LOG = 5

    @property
    def priority(self) -> int:
        """Scheduler priority, 1 = highest."""
        return _PRIORITY[self]

    @property
    def is_bulk_class(self) -> bool:
        """BULK and LOG share at most half of the window (rule S0)."""
        return self in (Endpoint.BULK, Endpoint.LOG)


_PRIORITY = {
    Endpoint.LINK: 0,
    Endpoint.SYSTEM: 1,
    Endpoint.TABLES: 2,
    Endpoint.ZIGBEE: 3,
    Endpoint.BULK: 4,
    Endpoint.LOG: 5,
}

DATA_ENDPOINTS = (
    Endpoint.SYSTEM,
    Endpoint.ZIGBEE,
    Endpoint.TABLES,
    Endpoint.BULK,
    Endpoint.LOG,
)

#: Endpoints in scheduler priority order.
BY_PRIORITY = tuple(sorted(DATA_ENDPOINTS, key=lambda e: e.priority))


class Kind(enum.IntEnum):
    REQUEST = 0
    RESPONSE = 1
    EVENT = 2


class Status(enum.IntEnum):
    """Message-level status codes (spec 6.4)."""

    SUCCESS = 0x00
    FAILURE = 0x01
    BUSY = 0x02
    INVALID_PARAMETER = 0x03
    UNSUPPORTED_COMMAND = 0x04
    INVALID_STATE = 0x05
    NOT_FOUND = 0x06
    NO_SPACE = 0x07
    TIMEOUT = 0x08
    LINK_RESET = 0x09
    ACCESS_DENIED = 0x0A
    NOT_FORMED = 0x0B
    ALREADY_EXISTS = 0x0C
    STORAGE_ERROR = 0x0D
    SECURITY_ERROR = 0x0E
    VERSION_MISMATCH = 0x0F
    IN_PROGRESS = 0x10
    TOO_LARGE = 0x11
    WRONG_ENDPOINT = 0x12
    CONFLICT = 0x13
    ABORTED = 0x14
    LINK_REJECTED = 0x15

    @classmethod
    def from_int(cls, value: int) -> Status | int:
        try:
            return cls(value)
        except ValueError:
            return value


class NcpCaps(enum.IntFlag):
    """NCP capability bits (spec 6.6)."""

    HOST_SOURCE_ROUTES = 1 << 0
    CONCENTRATOR = 1 << 1
    APS_FRAGMENTATION = 1 << 2
    INSTALL_CODES = 1 << 3
    KEY_EXPORT = 1 << 4
    IEEE_REWRITABLE = 1 << 5
    HOST_BACKED_TABLES = 1 << 6
    NCP_FW_UPDATE = 1 << 7
    GREEN_POWER_PROXY = 1 << 8
    ENERGY_SCAN = 1 << 9
    NETWORK_KEY_ROTATION = 1 << 10
    PACKET_CAPTURE = 1 << 12
    LINK_AUTH = 1 << 13
    EZSP_HASHED_TCLK = 1 << 14
    BACKUP_RESTORE = 1 << 15
    MANUFACTURER_CODE = 1 << 16
    GROUP_MEMBERSHIP = 1 << 17
    TX_POWER = 1 << 18
    INTERPAN = 1 << 19
    GREEN_POWER_SINK = 1 << 20
    PTA_COEX = 1 << 21
    UART_FLOW_CONTROL = 1 << 22


class HostCaps(enum.IntFlag):
    """Host capability bits (spec 8.8)."""

    HOST_TABLES = 1 << 0
    FC_CHECKPOINTS = 1 << 1
    RETRY_CACHE = 1 << 2
    GP_SHADOW = 1 << 3


class Capacity(enum.IntEnum):
    """Capacity IDs of ``SYS_NEGOTIATE`` (spec 6.6)."""

    MAX_APS_INFLIGHT = 1
    MAX_CHILDREN = 2
    LINK_KEY_CACHE = 3
    ADDRESS_MAP_CACHE = 4
    SOURCE_ROUTE_CACHE = 5
    MAX_ASDU = 6
    FC_STRIDE = 7
    MAX_HOST_ENDPOINTS = 8
    GROUP_TABLE = 9
    BINDING_TABLE = 10
    NEIGHBOR_TABLE = 11
    ROUTE_TABLE = 12
    MAX_RESTORE_RECORDS_PER_PUT = 13
    MAX_SOURCE_ROUTE_RELAYS = 14
    GP_SINK_TABLE = 15
    GP_PROXY_TABLE = 16
    MAX_NCP_REQUESTS = 17
    MAX_TC_DEVICES = 18
    HOST_RESPONSE_BYTES = 19


class NetworkState(enum.IntEnum):
    """``EVT_NCP_READY.network_state`` / ``NWK_GET_INFO.state``."""

    NONE = 0
    FORMED_DOWN = 1
    UP = 2


class ResetReasonNcp(enum.IntEnum):
    """``EVT_NCP_READY.reset_reason`` (spec 7.1)."""

    UNKNOWN = 0
    POWER_ON = 1
    SOFTWARE = 2
    WATCHDOG = 3
    BROWN_OUT = 4
    FIRMWARE_UPDATE = 5
    FATAL = 6
    HOST_REQUEST = 7
    HOST_EN_BOOT = 8


class TxOptions(enum.IntFlag):
    """``APS_DATA_REQUEST.tx_options`` (spec 7.3)."""

    NONE = 0
    APS_ACK = 1 << 0
    APS_SECURITY = 1 << 1
    FORCE_ROUTE_DISCOVERY = 1 << 2
    FRAGMENTATION = 1 << 3
    USE_ALIAS = 1 << 4
    EXTENDED_TIMEOUT = 1 << 5
    SOURCE_ROUTE = 1 << 6


class IndicationFlags(enum.IntFlag):
    """``EVT_APS_DATA_INDICATION.flags`` (spec 7.3)."""

    APS_SECURED = 1 << 0
    NWK_SECURED = 1 << 1
    SRC_IEEE_VALID = 1 << 2
    BROADCAST = 1 << 3
    GROUPCAST = 1 << 4
    REASSEMBLED = 1 << 5
    HANDLED_BY_NCP = 1 << 6
    LOCAL_LOOPBACK = 1 << 7


#: Confirm words.
FACTORY_RESET_CONFIRM = 0x46524553  # "FRES"
LOCK_CONFIRM = 0x4B434F4C  # "LOCK"

#: ``FRAME_COUNTER_RESERVATION_SIZE``.
FC_STRIDE = 0x400
