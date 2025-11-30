"""ESPHome Tailscale Component for ESP32-C3."""
from pathlib import Path
import logging

import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import time, esp32
from esphome.components.esp32 import add_idf_sdkconfig_option
from esphome.const import (
    CONF_ID,
    CONF_TIME_ID,
)
from esphome.core import CORE

DEPENDENCIES = ["network", "time", "esp32"]
CODEOWNERS = ["@alfs"]

# Reference external wireguard component
CONF_WIREGUARD_ID = "wireguard_id"
CONF_AUTH_KEY = "auth_key"
CONF_CONTROL_URL = "control_url"
CONF_DEVICE_NAME = "device_name"
CONF_HOSTNAME = "hostname"
CONF_UPDATE_INTERVAL = "update_interval"
CONF_CONTROL_PUBLIC_KEY = "control_public_key"
CONF_CONTROL_PSK = "control_psk"
CONF_DISCO_PING_TARGETS = "allowed_peers"
CONF_PREFERRED_DERP = "preferred_derp"
CONF_PREFER_DIRECT_UDP = "prefer_direct_udp"
CONF_STATUS_LED = "status_led"
CONF_STATUS_LED_PIN = "pin"
CONF_STATUS_LED_ENABLED = "enabled"

tailscale_ns = cg.esphome_ns.namespace("tailscale")
TailscaleComponent = tailscale_ns.class_("TailscaleComponent", cg.PollingComponent)

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(): cv.declare_id(TailscaleComponent),
        cv.Required(CONF_AUTH_KEY): cv.string,
        cv.Required(CONF_CONTROL_URL): cv.url,
        cv.Optional(CONF_DEVICE_NAME): cv.string,
        cv.Optional(CONF_HOSTNAME): cv.hostname,
        cv.Required(CONF_TIME_ID): cv.use_id(time.RealTimeClock),
        cv.Optional(CONF_WIREGUARD_ID): cv.use_id(cg.Component),
        cv.Optional(CONF_CONTROL_PUBLIC_KEY): cv.string,
        cv.Optional(CONF_CONTROL_PSK): cv.string,
        cv.Optional(CONF_UPDATE_INTERVAL, default="60s"): cv.positive_time_period_milliseconds,
        cv.Optional(CONF_DISCO_PING_TARGETS): cv.ensure_list(cv.string),
        cv.Optional(CONF_PREFERRED_DERP, default=28): cv.int_range(min=0, max=999),
        cv.Optional(CONF_PREFER_DIRECT_UDP, default=False): cv.boolean,
        cv.Optional(CONF_STATUS_LED): cv.Schema({
            cv.Optional(CONF_STATUS_LED_ENABLED, default=True): cv.boolean,
            cv.Optional(CONF_STATUS_LED_PIN, default=10): cv.int_range(min=0, max=48),
        }),
    }
).extend(cv.polling_component_schema("60s"))


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)

    # Add required libraries
    cg.add_library("droscy/esp_wireguard", "0.4.2")
    cg.add_library("esphome/libsodium", "1.10020.7")

    # Configure esp_wireguard library for dynamic peer switching
    # Keep only 1 active WireGuard session, dynamically switch between peers using LRU eviction
    cg.add_build_flag("-DCONFIG_WIREGUARD_MAX_PEERS=1")

    # Use linker wrapping to replace libsodium's sodium_init with our ESP32-C3 safe version
    cg.add_build_flag("-Wl,--wrap=sodium_init")

    # Add vendored noise-c library (minimal subset for Noise_IK_25519_ChaChaPoly_BLAKE2s)
    component_dir = Path(__file__).resolve().parent
    noise_dir = component_dir / "noise"
    logging.warning(f"Using vendored noise-c from: {noise_dir}")

    # Add noise-c as a library from the vendored directory
    file_url = f"file://{noise_dir.resolve()}"
    cg.add_library("noise-c-vendored", "0.1.10", file_url)

    # Add include paths for noise-c headers
    cg.add_build_flag(f"-I{noise_dir.resolve()}/include")
    cg.add_build_flag(f"-I{noise_dir.resolve()}/src")
    cg.add_build_flag(f"-I{noise_dir.resolve()}/src/crypto/blake2")

    # Legacy defines for compatibility (configuration is now in defines.h)
    cg.add_build_flag("-DUSE_LIBSODIUM=1")
    cg.add_build_flag("-DUSE_SODIUM=1")
    
    # Enable certificate bundle for HTTPS
    add_idf_sdkconfig_option("CONFIG_MBEDTLS_CERTIFICATE_BUNDLE", True)
    
    # DERP support disabled for now - causes Kconfig build issues
    # TODO: Re-enable once esp_websocket_client component is properly integrated
    # cg.add_define("USE_DERP")
    # esp32.add_idf_component(
    #     name="esp_websocket_client",
    #     repo="https://github.com/espressif/esp-protocols",
    #     path="components/esp_websocket_client",
    #     ref="mdns-v1.8.2",
    # )

    # Set basic config
    cg.add(var.set_auth_key(config[CONF_AUTH_KEY]))
    cg.add(var.set_control_url(config[CONF_CONTROL_URL]))
    
    if CONF_CONTROL_PUBLIC_KEY in config:
        cg.add(var.set_control_public_key(config[CONF_CONTROL_PUBLIC_KEY]))
    
    if CONF_DEVICE_NAME in config:
        cg.add(var.set_device_name(config[CONF_DEVICE_NAME]))
    elif CONF_HOSTNAME in config:
        cg.add(var.set_device_name(config[CONF_HOSTNAME]))
    else:
        cg.add(var.set_device_name(CORE.name))
    
    # Set time source
    time_component = await cg.get_variable(config[CONF_TIME_ID])
    cg.add(var.set_time_source(time_component))
    
    # Optional control server public key and PSK
    if CONF_CONTROL_PUBLIC_KEY in config:
        cg.add(var.set_control_public_key(config[CONF_CONTROL_PUBLIC_KEY]))
    if CONF_CONTROL_PSK in config:
        cg.add(var.set_control_psk(config[CONF_CONTROL_PSK]))
    
    # Set wireguard component reference if provided
    if CONF_WIREGUARD_ID in config:
        wg_component = await cg.get_variable(config[CONF_WIREGUARD_ID])
        cg.add_define("USE_WIREGUARD")
        cg.add(var.set_wireguard_component(wg_component))
    
    # Set disco ping targets if provided
    if CONF_DISCO_PING_TARGETS in config:
        for target in config[CONF_DISCO_PING_TARGETS]:
            cg.add(var.add_disco_ping_target(target))

    # Set preferred DERP region
    cg.add(var.set_preferred_derp(config[CONF_PREFERRED_DERP]))

    # Set direct UDP preference
    cg.add(var.set_prefer_direct_udp(config[CONF_PREFER_DIRECT_UDP]))

    # Configure status LED
    if CONF_STATUS_LED in config:
        led_config = config[CONF_STATUS_LED]
        cg.add(var.set_status_led_enabled(led_config[CONF_STATUS_LED_ENABLED]))
        cg.add(var.set_status_led_pin(led_config[CONF_STATUS_LED_PIN]))
