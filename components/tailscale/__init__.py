"""ESPHome Tailscale Component for ESP32-C3."""
from pathlib import Path
import logging
import subprocess
import sys

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
    }
).extend(cv.polling_component_schema("60s"))


def ensure_noise_c_patched(repo_root: Path) -> None:
    """Apply noise-c patch files before compiling."""
    patch_script = repo_root / "scripts" / "apply_noise_c_patches.py"
    if not patch_script.exists():
        logging.warning("noise-c patch script missing at %s", patch_script)
        return

    python = sys.executable or "python3"
    logging.warning("Ensuring noise-c patches are applied via %s", patch_script)
    try:
        subprocess.run([python, str(patch_script)], cwd=str(repo_root), check=True)
    except FileNotFoundError as err:
        raise cv.Invalid(f"Failed to execute {patch_script}: {err}") from err
    except subprocess.CalledProcessError as err:
        raise cv.Invalid(
            "noise-c patches could not be applied; see logs above for details"
        ) from err


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)

    # Add required libraries
    cg.add_library("droscy/esp_wireguard", "0.4.2")
    cg.add_library("esphome/libsodium", "1.10020.7")
    
    # Use linker wrapping to replace libsodium's sodium_init with our ESP32-C3 safe version
    cg.add_build_flag("-Wl,--wrap=sodium_init")
    
    # Add noise-c library from local directory
    repo_root = Path(__file__).resolve().parents[2]  # Up to tailscale-iot root (components/tailscale/__init__.py -> components -> tailscale-iot)
    ensure_noise_c_patched(repo_root)
    noise_dir = repo_root / "external" / "required" / "noise-c"
    logging.warning(f"Noise-c path: {noise_dir}, exists: {noise_dir.exists()}")
    if noise_dir.exists():
        # Add noise-c directory to library search paths
        lib_extra_dir = str(noise_dir.parent.resolve())
        logging.warning(f"Adding lib_extra_dirs: {lib_extra_dir}")
        cg.add_platformio_option("lib_extra_dirs", [lib_extra_dir])
        # Add noise-c as a library with version matching library.json
        file_url = f"file://{noise_dir.resolve()}"
        logging.warning(f"Adding noise-c library: {file_url}")
        cg.add_library("noise-c", "0.1.10", file_url)
        # Add include paths for noise-c headers
        src_include = f"-I{noise_dir.resolve()}/src"
        logging.warning(f"Adding build flag: {src_include}")
        cg.add_build_flag(src_include)
        
        # Enable noise-c features with preprocessor defines
        # These must be set BEFORE noise-c headers are included to configure the library
        cg.add_build_flag("-DNOISE_USE_BLAKE2S=1")           # Required for Tailscale TS2021
        cg.add_build_flag("-DNOISE_USE_REFERENCE_BACKEND=1")  # Required for BLAKE2s (not in libsodium)
        cg.add_build_flag("-DNOISE_USE_LIBSODIUM=1")         # Use libsodium for Curve25519 & ChaCha20-Poly1305
        
        # Legacy defines for compatibility
        cg.add_build_flag("-DUSE_LIBSODIUM=1")
        cg.add_build_flag("-DUSE_SODIUM=1")
        
        # Add reference backend include path
        ref_backend = noise_dir / "src" / "backend" / "ref"
        if ref_backend.exists():
            cg.add_build_flag(f"-I{ref_backend.resolve()}")
            logging.warning(f"Added reference backend include: {ref_backend}")
        
        logging.warning("Enabled noise-c: BLAKE2s=1, REFERENCE_BACKEND=1, LIBSODIUM=1")
    else:
        logging.error(f"noise-c directory not found at {noise_dir}")
    
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
