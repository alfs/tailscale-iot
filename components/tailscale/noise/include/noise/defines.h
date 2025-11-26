/*
 * MODIFIED FILE - Hardcoded configuration for tailscale-iot ESP32
 *
 * Original: noise-c/include/noise/defines.h
 * Source: https://github.com/rweather/noise-c
 * Version: 0.1.10 (commit 62f156160cab724b648d24fa1e39643561ad8770)
 * License: MIT - Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 *
 * Modifications:
 * - Replaced conditional compilation with hardcoded values
 * - Only enables algorithms needed for Noise_IK_25519_ChaChaPoly_BLAKE2s
 * - Configured for libsodium backend with reference BLAKE2s
 */

#pragma once

/* Algorithms we use */
#define NOISE_USE_CURVE25519         1
#define NOISE_USE_CHACHAPOLY         1
#define NOISE_USE_BLAKE2S            1
#define NOISE_USE_POLY1305           1

/* Algorithms we don't use */
#define NOISE_USE_AES                0
#define NOISE_USE_BLAKE2B            0
#define NOISE_USE_SHA256             0
#define NOISE_USE_SHA512             0
#define NOISE_USE_ED25519            0
#define NOISE_USE_SIGN               0

/* Backend selection:
 * - libsodium for ChaCha20-Poly1305 and Curve25519 (optimized)
 * - reference backend for BLAKE2s only (not in libsodium)
 */
#define NOISE_USE_LIBSODIUM          1
#define NOISE_USE_REFERENCE_BACKEND  1
#define NOISE_USE_OPENSSL            0

/* Reference backend sub-options (only BLAKE2s enabled) */
#define NOISE_USE_REFERENCE_BLAKE2S  1
#define NOISE_USE_REFERENCE_BLAKE2B  0
#define NOISE_USE_REFERENCE_CHACHA   0
#define NOISE_USE_REFERENCE_POLY1305 0
#define NOISE_USE_REFERENCE_SHA256   0
#define NOISE_USE_REFERENCE_DONNA_CURVE25519  0
#define NOISE_USE_REFERENCE_STROBE_CURVE25519 0

/* Use custom RNG (provided by tailscale.cpp via esp_fill_random) */
#define NOISE_USE_CUSTOM_RAND        1

/* No threading needed on ESP32 */
#define NOISE_USE_PTHREAD            0
