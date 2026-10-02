#include <cassert>
#include <cstdint>
#include <vector>

#include "hpack_status.h"
int main() {
  // Fixtures from Python hpack's independent Encoder with header_table_size=0.
  const std::vector<std::pair<int, std::vector<uint8_t>>> fixtures = {
      {200, {0x20, 0x88}},
      {201, {0x20, 0x48, 0x82, 0x10, 0x03}},
      {204, {0x20, 0x89}},
      {301, {0x20, 0x48, 0x82, 0x64, 0x01}},
      {403, {0x20, 0x48, 0x83, 0x68, 0x0c, 0xff}},
      {404, {0x20, 0x8d}},
      {429, {0x20, 0x48, 0x83, 0x68, 0x4f, 0xff}},
      {500, {0x20, 0x8e}},
      {503, {0x20, 0x48, 0x83, 0x6c, 0x0c, 0xff}},
      {400, {0x08, 0x03, '4', '0', '0'}}};
  for (const auto &[expected, bytes] : fixtures) {
    assert(esphome::tailscale::hpack::status(bytes.data(), bytes.size()) ==
           expected);
    for (size_t length = 0; length < bytes.size(); ++length)
      assert(esphome::tailscale::hpack::status(bytes.data(), length) == -1);
  }
  assert(esphome::tailscale::hpack::status(nullptr, 100) == -1);
  for (const std::vector<uint8_t> &invalid :
       {std::vector<uint8_t>{0xbe},
        {0x21, 0x88},
        {0x48, 0x03, '6', '0', '0'},
        {0x48, 0x82, 0x10, 0x00},
        {0x48, 0x83, 0x68, 0x0c, 0xfe},
        {0x48, 0x81, 0xff},
        {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
        {0x48, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff}})
    assert(esphome::tailscale::hpack::status(invalid.data(), invalid.size()) ==
           -1);
}
