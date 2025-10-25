# CMake configuration for noise-c library integration
# This file is included from the main component CMakeLists.txt

set(NOISE_C_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../external/required/noise-c")

# Noise-C protocol sources
set(NOISE_PROTOCOL_SRCS
    "${NOISE_C_DIR}/src/protocol/cipherstate.c"
    "${NOISE_C_DIR}/src/protocol/dhstate.c"
    "${NOISE_C_DIR}/src/protocol/errors.c"
    "${NOISE_C_DIR}/src/protocol/handshakestate.c"
    "${NOISE_C_DIR}/src/protocol/hashstate.c"
    "${NOISE_C_DIR}/src/protocol/internal.c"
    "${NOISE_C_DIR}/src/protocol/names.c"
    "${NOISE_C_DIR}/src/protocol/patterns.c"
    "${NOISE_C_DIR}/src/protocol/randstate.c"
    "${NOISE_C_DIR}/src/protocol/symmetricstate.c"
    "${NOISE_C_DIR}/src/protocol/util.c"
)

# Reference implementation crypto backends
set(NOISE_BACKEND_SRCS
    "${NOISE_C_DIR}/src/backend/ref/cipher-chachapoly.c"
    "${NOISE_C_DIR}/src/backend/ref/dh-curve25519.c"
    "${NOISE_C_DIR}/src/backend/ref/hash-blake2s.c"
)

# Include directories
set(NOISE_INCLUDE_DIRS
    "${NOISE_C_DIR}/include"
    "${NOISE_C_DIR}/src"
)

# Compiler definitions for reference backend
set(NOISE_COMPILE_DEFINITIONS
    USE_LIBSODIUM=0
    USE_OPENSSL=0
)

# Add all noise-c sources to the component
list(APPEND COMPONENT_SRCS ${NOISE_PROTOCOL_SRCS} ${NOISE_BACKEND_SRCS})

# Add include directories
list(APPEND COMPONENT_ADD_INCLUDEDIRS ${NOISE_INCLUDE_DIRS})

# Add compile definitions
list(APPEND COMPONENT_PRIV_REQUIRES mbedtls)
