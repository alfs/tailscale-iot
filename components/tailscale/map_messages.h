#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <new>

namespace esphome::tailscale {
// Tailscale map messages have a little-endian length prefix. Keep partial
// messages between nonblocking polls, and return one message at a time even
// when a DATA frame contains several. Storage is allocated lazily for the
// streaming session.
template <size_t Capacity = 65536> class MapMessages {
public:
  enum class Result { More, Ready, Invalid };
  Result feed(const uint8_t *input, size_t size, size_t &consumed) {
    consumed = 0;
    if (invalid_ || (!input && size))
      return Result::Invalid;
    while (consumed < size) {
      if (prefixSize_ < 4) {
        prefix_[prefixSize_++] = input[consumed++];
        if (prefixSize_ < 4)
          continue;
        wanted_ = uint32_t(prefix_[0]) | (uint32_t(prefix_[1]) << 8) |
                  (uint32_t(prefix_[2]) << 16) | (uint32_t(prefix_[3]) << 24);
        if (!wanted_ || wanted_ >= Capacity) {
          invalid_ = true;
          return Result::Invalid;
        }
      }
      if (wanted_ + 1 > allocated_) {
        // Grow geometrically to avoid reallocating for every slightly larger
        // map. The prefix is bounded before allocation; retain storage for
        // reuse.
        size_t target = allocated_ ? allocated_ * 2 : 256;
        if (target < wanted_ + 1)
          target = wanted_ + 1;
        if (target > Capacity)
          target = Capacity;
        // A new prefix invalidates the previously returned message. No partial
        // body needs preserving here; release it before growing to avoid a
        // transient old+new buffer peak on devices without PSRAM.
        message_.reset();
        allocated_ = 0;
        message_.reset(new (std::nothrow) char[target]);
        if (!message_) {
          invalid_ = true;
          return Result::Invalid;
        }
        allocated_ = target;
      }
      const size_t available = size - consumed;
      const size_t needed = wanted_ - used_;
      const size_t count = available < needed ? available : needed;
      memcpy(message_.get() + used_, input + consumed, count);
      consumed += count;
      used_ += count;
      if (used_ == wanted_) {
        message_[used_] = '\0';
        delivered_ = used_;
        used_ = prefixSize_ = wanted_ = 0;
        return Result::Ready;
      }
    }
    return Result::More;
  }
  void reset() {
    prefixSize_ = used_ = wanted_ = delivered_ = 0;
    invalid_ = false;
  }
  const char *data() const { return message_.get(); }
  size_t size() const { return delivered_; }
  size_t allocated_capacity() const { return allocated_; }

private:
  static_assert(Capacity > 1, "Map capacity must include a terminator");
  std::unique_ptr<char[]> message_;
  size_t allocated_{0};
  uint8_t prefix_[4]{};
  size_t prefixSize_{0}, used_{0}, wanted_{0}, delivered_{0};
  bool invalid_{false};
};
} // namespace esphome::tailscale
