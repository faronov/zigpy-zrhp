"""Configuration schema of the ``zrhp`` radio type."""

from __future__ import annotations

import voluptuous as vol
from zigpy.config import (  # noqa: F401
    CONF_DATABASE,
    CONF_DEVICE,
    CONF_DEVICE_BAUDRATE,
    CONF_DEVICE_FLOW_CONTROL,
    CONF_DEVICE_PATH,
    CONFIG_SCHEMA,
    SCHEMA_DEVICE,
    cv_boolean,
)

#: Thread BR board / USB-UART bridge default (spec 4.1, decision N10).
DEFAULT_BAUDRATE = 921_600
#: The no-flow-control fallback rate (spec 4.4, 11.5).
FALLBACK_BAUDRATE = 460_800

CONF_ZRHP_CONFIG = "zrhp_config"
CONF_BAUDRATE_FALLBACK = "baudrate_fallback"
CONF_SIDECAR_PATH = "sidecar_path"
CONF_RESUME_BUDGET = "resume_budget"
CONF_USJ_RESET = "hard_reset_on_resume_failure"
CONF_LOCK_KEY_EXPORT = "lock_key_export_after_backup"
CONF_GP_SINK = "gp_sink"
CONF_GP_SECURITY_LEVEL = "gp_security_level"
CONF_CONNECT_TIMEOUT = "connect_timeout"
CONF_CONFIRM_TIMEOUT = "confirm_timeout"
CONF_CONFIRM_TIMEOUT_EXTENDED = "confirm_timeout_extended"
CONF_TC_POLICY = "tc_policy"
CONF_MANUFACTURER_CODE = "manufacturer_code"

GP_SINK_NCP = "ncp"
GP_SINK_HOST = "host"

SCHEMA_DEVICE = SCHEMA_DEVICE.extend(
    {
        vol.Optional(CONF_DEVICE_BAUDRATE, default=DEFAULT_BAUDRATE): int,
        vol.Optional(CONF_DEVICE_FLOW_CONTROL, default=None): vol.In(
            ["hardware", "software", None]
        ),
    }
)

SCHEMA_TC_POLICY = vol.Schema(
    {
        vol.Optional("allow_join", default=1): vol.All(int, vol.Range(0, 2)),
        vol.Optional("require_tclk_update", default=1): vol.All(int, vol.Range(0, 1)),
        vol.Optional("allow_tc_rejoin", default=1): vol.All(int, vol.Range(0, 1)),
        vol.Optional("allow_app_link_keys", default=0): vol.All(int, vol.Range(0, 1)),
        vol.Optional("join_timeout_s", default=0): vol.All(int, vol.Range(0, 0xFFFF)),
    }
)

SCHEMA_ZRHP = vol.Schema(
    {
        vol.Optional(CONF_BAUDRATE_FALLBACK, default=True): cv_boolean,
        vol.Optional(CONF_SIDECAR_PATH, default=None): vol.Any(None, str),
        vol.Optional(CONF_RESUME_BUDGET, default=20.0): vol.All(
            vol.Coerce(float), vol.Range(min=1)
        ),
        vol.Optional(CONF_USJ_RESET, default=True): cv_boolean,
        vol.Optional(CONF_LOCK_KEY_EXPORT, default=False): cv_boolean,
        vol.Optional(CONF_GP_SINK, default=GP_SINK_NCP): vol.In([GP_SINK_NCP, GP_SINK_HOST]),
        vol.Optional(CONF_GP_SECURITY_LEVEL, default=0): vol.All(int, vol.Range(0, 3)),
        vol.Optional(CONF_CONNECT_TIMEOUT, default=5.0): vol.Coerce(float),
        vol.Optional(CONF_CONFIRM_TIMEOUT, default=10.0): vol.Coerce(float),
        vol.Optional(CONF_CONFIRM_TIMEOUT_EXTENDED, default=40.0): vol.Coerce(float),
        vol.Optional(CONF_TC_POLICY, default={}): SCHEMA_TC_POLICY,
        vol.Optional(CONF_MANUFACTURER_CODE, default=None): vol.Any(
            None, vol.All(int, vol.Range(0, 0xFFFF))
        ),
    }
)

CONFIG_SCHEMA = CONFIG_SCHEMA.extend(
    {
        vol.Required(CONF_DEVICE): SCHEMA_DEVICE,
        vol.Optional(CONF_ZRHP_CONFIG, default={}): SCHEMA_ZRHP,
    }
)
