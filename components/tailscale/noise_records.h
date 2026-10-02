#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
namespace esphome::tailscale::control_records {
// Official controlbase records are at most 4096 bytes; the WebSocket layer
// delivers at most 8192. One incomplete record plus one chunk fits here.
class Records {
public:
  enum class State { Incomplete, Invalid, Ready };
  static constexpr size_t Capacity = 12288;
  bool append(const uint8_t *bytes, size_t size) {
    if ((!bytes && size) || size > Capacity - (end_ - begin_))
      return false;
    if (size > Capacity - end_) {
      // Compact only when an incoming chunk cannot fit in the tail.
      const size_t pending = end_ - begin_;
      memmove(buffer_, buffer_ + begin_, pending);
      begin_ = 0;
      end_ = pending;
    }
    if (size)
      memcpy(buffer_ + end_, bytes, size);
    end_ += size;
    return true;
  }
  State state() const {
    if (end_ - begin_ < 3)
      return State::Incomplete;
    const size_t size = ciphertextSize();
    if (buffer_[begin_] != 4 || size < 16 || size > 4093)
      return State::Invalid;
    return end_ - begin_ < size + 3 ? State::Incomplete : State::Ready;
  }
  const uint8_t *ciphertext() const { return buffer_ + begin_ + 3; }
  size_t ciphertextSize() const {
    return (size_t(buffer_[begin_ + 1]) << 8) | buffer_[begin_ + 2];
  }
  void consume() {
    if (state() != State::Ready)
      return;
    begin_ += ciphertextSize() + 3;
    if (begin_ == end_)
      begin_ = end_ = 0;
  }
  void clear() { begin_ = end_ = 0; }

private:
  uint8_t buffer_[Capacity]{}; // Long-lived transport object; no per-record
                               // allocation.
  size_t begin_{0}, end_{0};
};
} // namespace esphome::tailscale::control_records
