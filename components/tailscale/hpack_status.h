#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace esphome::tailscale::hpack {
// A bounded status extractor for a connection advertising HEADER_TABLE_SIZE=0.
// HTTP/2 response pseudo-headers precede ordinary headers. Unsupported
// encodings fail closed; this does not pretend to be a general HPACK header
// decoder.
inline bool integer(const uint8_t *data, size_t length, size_t &at,
                    unsigned bits, uint32_t &value) {
  if (at >= length)
    return false;
  const uint32_t mask = (1u << bits) - 1;
  value = data[at++] & mask;
  if (value < mask)
    return true;
  for (unsigned shift = 0; shift <= 28 && at < length; shift += 7) {
    const uint8_t byte = data[at++];
    const uint32_t part = byte & 127;
    if (part > (UINT32_MAX - value) >> shift)
      return false;
    value += part << shift;
    if (!(byte & 128))
      return true;
  }
  return false;
}
inline int status(const uint8_t *data, size_t length) {
  if (!data || !length)
    return -1;
  size_t at = 0;
  while (at < length && (data[at] & 0xe0) == 0x20) {
    uint32_t tableSize;
    if (!integer(data, length, at, 5, tableSize) || tableSize != 0)
      return -1;
  }
  if (at >= length)
    return -1;
  const uint8_t prefix = data[at];
  uint32_t index;
  if (prefix & 0x80) {
    if (!integer(data, length, at, 7, index) || index < 8 || index > 14)
      return -1;
    static constexpr int codes[] = {200, 204, 206, 304, 400, 404, 500};
    return codes[index - 8];
  }
  if (!integer(data, length, at, (prefix & 0x40) ? 6 : 4, index))
    return -1;
  if (index == 0) {
    if (at >= length || (data[at] & 0x80))
      return -1;
    uint32_t nameLength;
    if (!integer(data, length, at, 7, nameLength) || nameLength != 7 ||
        length - at < 7 || memcmp(data + at, ":status", 7))
      return -1;
    at += 7;
  } else if (index < 8 || index > 14) {
    return -1;
  }
  if (at >= length)
    return -1;
  const bool huffman = data[at] & 0x80;
  uint32_t valueLength;
  if (!integer(data, length, at, 7, valueLength) || valueLength > length - at)
    return -1;
  int result = 0;
  if (!huffman) {
    if (valueLength != 3)
      return -1;
    for (unsigned i = 0; i < 3; ++i) {
      if (data[at + i] < '0' || data[at + i] > '9')
        return -1;
      result = result * 10 + data[at + i] - '0';
    }
  } else {
    // Only decimal digits are valid in :status. RFC 7541's digit codes use
    // five bits for 0..2, six for 3..9; trailing EOS padding is at most 7 ones.
    if (valueLength < 2 || valueLength > 3)
      return -1;
    uint32_t code = 0;
    unsigned bits = 0, digits = 0;
    for (size_t i = 0; i < valueLength * 8; ++i) {
      code = (code << 1) | ((data[at + i / 8] >> (7 - i % 8)) & 1);
      ++bits;
      int digit = bits == 5 && code <= 2 ? static_cast<int>(code)
                  : bits == 6 && code >= 25 && code <= 31
                      ? static_cast<int>(code - 22)
                      : -1;
      if (digits < 3 && digit >= 0) {
        result = result * 10 + digit;
        ++digits;
        code = bits = 0;
      } else if (digits < 3 && bits >= 6)
        return -1;
    }
    if (digits != 3 || bits > 7 || code != (1u << bits) - 1)
      return -1;
  }
  return result >= 100 && result <= 599 ? result : -1;
}
} // namespace esphome::tailscale::hpack
