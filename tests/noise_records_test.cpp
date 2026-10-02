#include "noise_records.h"
#include <cassert>
#include <vector>
int main() {
  using namespace esphome::tailscale::control_records;
  const std::vector<uint8_t> record{4, 0, 16, 1,  2,  3,  4,  5,  6, 7,
                                    8, 9, 10, 11, 12, 13, 14, 15, 16};
  for (size_t split = 0; split <= record.size(); ++split) {
    Records r;
    assert(r.append(record.data(), split));
    assert(r.state() == (split == record.size() ? Records::State::Ready
                                                : Records::State::Incomplete));
    assert(r.append(record.data() + split, record.size() - split));
    assert(r.state() == Records::State::Ready);
    assert(r.ciphertextSize() == 16 && r.ciphertext()[15] == 16);
    r.consume();
    assert(r.state() == Records::State::Incomplete);
  }
  Records combined;
  assert(combined.append(record.data(), record.size()));
  assert(combined.append(record.data(), record.size()));
  combined.consume();
  assert(combined.state() == Records::State::Ready);
  combined.consume();
  assert(combined.state() == Records::State::Incomplete);
  for (auto bytes : std::vector<std::vector<uint8_t>>{
           {3, 0, 16}, {4, 0, 15}, {4, 16, 0}, {4, 255, 255}}) {
    Records r;
    assert(r.append(bytes.data(), bytes.size()));
    assert(r.state() == Records::State::Invalid);
  }
  Records limit;
  std::vector<uint8_t> huge(Records::Capacity + 1, 0);
  assert(!limit.append(huge.data(), huge.size()));
  assert(limit.append(huge.data(), Records::Capacity));
  assert(!limit.append(huge.data(), 1));
  limit.clear();
  assert(limit.state() == Records::State::Incomplete);

  // Consume many coalesced records, then force a tail compaction on append.
  Records cursor;
  std::vector<uint8_t> batch;
  for (unsigned i = 0; i < 640; ++i) {
    auto item = record;
    item[3] = uint8_t(i);
    batch.insert(batch.end(), item.begin(), item.end());
  }
  assert(cursor.append(batch.data(), batch.size()));
  for (unsigned i = 0; i < 400; ++i) {
    assert(cursor.state() == Records::State::Ready &&
           cursor.ciphertext()[0] == uint8_t(i));
    cursor.consume();
  }
  const auto *before = cursor.ciphertext();
  cursor.consume();
  assert(cursor.ciphertext() ==
         before + record.size()); // No per-record payload shift.
  batch.clear();
  for (unsigned i = 640; i < 1040; ++i) {
    auto item = record;
    item[3] = uint8_t(i);
    batch.insert(batch.end(), item.begin(), item.end());
  }
  assert(cursor.append(batch.data(), batch.size()));
  for (unsigned i = 401; i < 1040; ++i) {
    assert(cursor.state() == Records::State::Ready &&
           cursor.ciphertext()[0] == uint8_t(i));
    cursor.consume();
  }
  assert(cursor.state() == Records::State::Incomplete);
  assert(!cursor.append(nullptr, 1));
  cursor.consume(); // Safe even with no complete header.
}
