from pathlib import Path

import esphome.codegen as cg
from esphome.components import time
from esphome.components import wireguard
from esphome.components import esp32
from esphome.components.esp32 import add_idf_sdkconfig_option
import esphome.config_validation as cv
from esphome.const import CONF_ID, CONF_TIME_ID

CODEOWNERS = ["@tailscale"]
DEPENDENCIES = ["network", "time"]

CONF_AUTH_KEY = "auth_key"
CONF_CONTROL_URL = "control_url"
CONF_DEVICE_NAME = "device_name"
CONF_WIREGUARD_ID = "wireguard_id"
CONF_CONTROL_PUBLIC_KEY = "control_public_key"
CONF_CONTROL_PSK = "control_psk"
CONF_NODE_KEY = "node_key"
CONF_MACHINE_KEY = "machine_key"

CONF_DEFAULT_POLLING_INTERVAL = "30s"

def validate_tailscale_key(key_type):
    """Validate that a Tailscale key has the correct type prefix."""
    def validator(value):
        if not value.startswith(f"{key_type}:"):
            raise cv.Invalid(f"Key must start with '{key_type}:' prefix. Example: '{key_type}:abcd1234...'")
        return value
    return validator

TAILSCALE_NS = cg.esphome_ns.namespace("tailscale_control")
TailscaleControlComponent = TAILSCALE_NS.class_(
    "TailscaleControlComponent", cg.Component, cg.PollingComponent
)

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(): cv.declare_id(TailscaleControlComponent),
        cv.GenerateID(CONF_TIME_ID): cv.use_id(time.RealTimeClock),
        cv.Required(CONF_AUTH_KEY): cv.string,
        cv.Optional(CONF_CONTROL_URL, default="https://controlplane.tailscale.com"): cv.string,
        cv.Optional(CONF_DEVICE_NAME, default="esp32c3-node"): cv.string,
        cv.Optional(CONF_CONTROL_PUBLIC_KEY): cv.string,
        cv.Optional(CONF_CONTROL_PSK): cv.string,
        cv.Optional(CONF_NODE_KEY): cv.All(cv.string, validate_tailscale_key("nodekey")),
        cv.Optional(CONF_MACHINE_KEY): cv.All(cv.string, validate_tailscale_key("mkey")),
        cv.Optional(CONF_WIREGUARD_ID): cv.use_id(wireguard.Wireguard),
    }
).extend(cv.polling_component_schema(CONF_DEFAULT_POLLING_INTERVAL))


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])

    await cg.register_component(var, config)

    # Ensure the underlying esp_wireguard library (and crypto helpers) are present even if the
    # dedicated WireGuard component is not directly referenced.
    cg.add_library("droscy/esp_wireguard", "0.4.2")
    cg.add_library("esphome/libsodium", "1.10020.7")
    
    # MessagePack support disabled temporarily due to compilation complexity
    # Will re-add after confirming JSON parsing works
    # cg.add_library("hideakitai/MsgPack", "^0.4.0")
    
    # Use linker wrapping to replace libsodium's sodium_init with our ESP32-C3 safe version
    cg.add_build_flag("-Wl,--wrap=sodium_init")

    repo_root = Path(__file__).resolve().parents[4]
    noise_dir = repo_root / "noise-c"
    if noise_dir.exists():
        cg.add_platformio_option("lib_extra_dirs", [str(noise_dir)])
        # IMPORTANT: Version must match library.json to force rebuild
        cg.add_library("noise-c", "0.1.11-bigendian", f"file://{noise_dir}")
        # Add noise-c src directory to include path for crypto headers
        cg.add_build_flag(f"-I{noise_dir}/src")
    add_idf_sdkconfig_option("CONFIG_MBEDTLS_CERTIFICATE_BUNDLE", True)

    cg.add(var.set_auth_key(config[CONF_AUTH_KEY]))
    cg.add(var.set_control_url(config[CONF_CONTROL_URL]))
    cg.add(var.set_device_name(config[CONF_DEVICE_NAME]))
    cg.add(var.set_time_component(await cg.get_variable(config[CONF_TIME_ID])))

    cg.add_define("USE_DERP")
    esp32.add_idf_component(
        name="esp_websocket_client",
        repo="https://github.com/espressif/esp-protocols",
        path="components/esp_websocket_client",
        ref="mdns-v1.8.2",
    )

    if CONF_CONTROL_PUBLIC_KEY in config:
        cg.add(var.set_control_public_key(config[CONF_CONTROL_PUBLIC_KEY]))
    if CONF_CONTROL_PSK in config:
        cg.add(var.set_control_psk(config[CONF_CONTROL_PSK]))

    if CONF_WIREGUARD_ID in config:
        wireguard_var = await cg.get_variable(config[CONF_WIREGUARD_ID])
        cg.add_define("USE_WIREGUARD")
        cg.add(var.set_wireguard_component(wireguard_var))
