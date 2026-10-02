#include <algorithm>
#include <cassert>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>
// Expose frame bookkeeping only to the host regression fixture.
#define private public
#include "http2_session.h"
#undef private
using namespace esphome::tailscale;
using Frame = Http2Session::Frame;
class Fixture : public Http2Session {
public:
  unsigned pulls = 0;
  std::vector<uint8_t> pending;
  std::vector<Frame> sent;
  Fixture() {
    response_buffer_ = scratch;
    settings_exchanged_ = true;
    persistent_stream_ = 3;
    recv_cb_ = [this](std::vector<uint8_t> &out, uint32_t) {
      ++pulls;
      out.swap(pending);
      return !out.empty();
    };
    send_cb_ = [this](const uint8_t *bytes, size_t size) {
      assert(size >= 9);
      Frame f;
      f.type = bytes[3];
      f.flags = bytes[4];
      f.stream_id = (uint32_t(bytes[5]) << 24) | (uint32_t(bytes[6]) << 16) |
                    (uint32_t(bytes[7]) << 8) | bytes[8];
      f.payload.assign(bytes + 9, bytes + size);
      f.length = f.payload.size();
      sent.push_back(std::move(f));
      return true;
    };
  }
  char scratch[2048]{};
};

int main() {
  Frame f;
  Fixture c;
  c.recv_buffer_ = {0, 0, 0, 4, 1, 0, 0, 0, 0, 0, 0,
                    3, 0, 1, 0, 0, 0, 3, 1, 2, 3};
  assert(c.read_frame_(f, 1) && f.type == 4 && c.pulls == 0 &&
         c.recv_buffer_.size() == 12);
  assert(c.read_frame_(f, 1) && f.type == 0 && f.length == 3 &&
         f.stream_id == 3 && c.pulls == 0);
  // Every frame owns its payload and consumes the socket bytes exactly once.
  assert(c.recv_buffer_.empty() &&
         f.payload == std::vector<uint8_t>({1, 2, 3}));
  Fixture partial;
  partial.recv_buffer_ = {0, 0, 0, 4};
  assert(!partial.read_frame_(f, 1) && partial.recv_buffer_.size() == 4);
  partial.pending = {1, 0, 0, 0, 0};
  assert(partial.read_frame_(f, 1) && f.type == 4 &&
         partial.recv_buffer_.empty());
  Fixture payload;
  payload.recv_buffer_ = {0, 0, 2, 6, 0, 0, 0, 0, 0, 42};
  assert(!payload.read_frame_(f, 1) && payload.recv_buffer_.size() == 10);
  payload.pending = {43};
  assert(payload.read_frame_(f, 1) &&
         f.payload == std::vector<uint8_t>({42, 43}));
  // A streaming-map DATA frame precedes the finite POST response in one read.
  // Deferring it must not consume, alter, or require new socket bytes for the
  // POST.
  Fixture interleaved;
  interleaved.deferred_.reserve(8);
  interleaved.recv_buffer_ = {0, 0, 3, 0, 0, 0, 0, 0, 3, 7,   8,
                              9, 0, 0, 1, 1, 0, 0, 0, 0, 5,   0x88,
                              0, 0, 2, 0, 1, 0, 0, 0, 5, '{', '}'};
  assert(interleaved.read_frame_(f, 1) && f.stream_id == 3);
  assert(interleaved.defer_frame_(std::move(f)));
  assert(interleaved.read_frame_(f, 1) && f.stream_id == 5 && f.type == 1 &&
         f.payload[0] == 0x88);
  assert(interleaved.read_frame_(f, 1) && f.stream_id == 5 && f.type == 0 &&
         f.payload == std::vector<uint8_t>({'{', '}'}));
  assert(interleaved.recv_buffer_.empty() && interleaved.pulls == 0);
  assert(!interleaved.take_frame_(5, f));
  assert(interleaved.take_frame_(3, f) &&
         f.payload == std::vector<uint8_t>({7, 8, 9}));
  assert(interleaved.deferred_bytes_ == 0 && interleaved.deferred_.empty());
  Frame unknown;
  unknown.stream_id = 7;
  assert(!interleaved.defer_frame_(std::move(unknown)));
  for (int i = 0; i < 8; i++) {
    Frame item;
    item.stream_id = 3;
    item.payload = {uint8_t(i)};
    assert(interleaved.defer_frame_(std::move(item)));
  }
  Frame ninth;
  ninth.stream_id = 3;
  assert(!interleaved.defer_frame_(std::move(ninth)));
  for (int i = 0; i < 8; i++)
    assert(interleaved.take_frame_(3, f) && f.payload[0] == i);
  Frame oversized;
  oversized.stream_id = 3;
  oversized.payload.resize(65537);
  assert(!interleaved.defer_frame_(std::move(oversized)) &&
         interleaved.deferred_bytes_ == 0);
  auto dataFrame = [](Fixture &session, const std::vector<uint8_t> &body,
                      uint8_t flags = 0) {
    auto &bytes = session.recv_buffer_;
    size_t n = body.size();
    bytes.insert(bytes.end(), {uint8_t(n >> 16), uint8_t(n >> 8), uint8_t(n), 0,
                               flags, 0, 0, 0, 3});
    bytes.insert(bytes.end(), body.begin(), body.end());
  };
  const std::string json = "{\"KeepAlive\":true}";
  std::vector<uint8_t> message = {uint8_t(json.size()), 0, 0, 0};
  message.insert(message.end(), json.begin(), json.end());
  // Every split, including a split length prefix, survives separate polling
  // calls.
  for (size_t split = 1; split < message.size(); split++) {
    Fixture fragmented;
    const char *result = nullptr;
    size_t size = 0;
    dataFrame(fragmented, {message.begin(), message.begin() + split});
    assert(!fragmented.read_next_message(3, result, size, 5));
    dataFrame(fragmented, {message.begin() + split, message.end()});
    assert(fragmented.read_next_message(3, result, size, 5) &&
           size == json.size() && std::string(result, size) == json);
    assert(fragmented.sent.size() == 4 && fragmented.recv_buffer_.empty());
  }
  // Coalesced messages are returned separately without losing the second one.
  Fixture combined;
  auto both = message;
  both.insert(both.end(), message.begin(), message.end());
  dataFrame(combined, both);
  const char *result = nullptr;
  size_t size = 0;
  assert(combined.read_next_message(3, result, size, 5) &&
         std::string(result, size) == json);
  assert(combined.read_next_message(3, result, size, 5) &&
         std::string(result, size) == json);
  Fixture zero;
  dataFrame(zero, {0, 0, 0, 0});
  assert(!zero.read_next_message(3, result, size, 5) && zero.stream_failed_);
  Fixture closed;
  dataFrame(closed, {}, 1);
  assert(!closed.read_next_message(3, result, size, 5) &&
         closed.stream_failed_);

  // Real finite POST must consume END_STREAM while retaining interleaved map
  // DATA.
  Fixture post;
  post.persistent_stream_ = 3;
  dataFrame(post, message);
  post.recv_buffer_.insert(post.recv_buffer_.end(),
                           {0,   0, 1, 1, 4, 0, 0, 0, 5, 0x88,
                            0,   0, 2, 0, 0, 0, 0, 0, 5, '{',
                            '}', 0, 0, 0, 0, 1, 0, 0, 0, 5});
  uint16_t status = 0;
  assert(post.post_json(5, "https", "control.example", "/machine/map", "{}",
                        result, size, status, 1000, true, false));
  assert(status == 200 && std::string(result, size) == "{}" &&
         post.recv_buffer_.empty() && post.pulls == 0);
  assert(post.read_next_message(3, result, size, 1000) &&
         std::string(result, size) == json);
  assert(post.init(post.send_cb_, post.recv_cb_));
  assert(!post.stream_failed() && post.deferred_.empty() &&
         post.persistent_stream_ == 0);

  // Small keepalives should not reserve a full 64 KiB map buffer.
  assert(combined.map_messages_.allocated_capacity() <= 512);
  MapMessages<1024> maps;
  auto feedMap = [](auto &assembler, const std::string &body) {
    std::vector<uint8_t> wire = {uint8_t(body.size()),
                                 uint8_t(body.size() >> 8), 0, 0};
    wire.insert(wire.end(), body.begin(), body.end());
    size_t consumed = 0;
    return assembler.feed(wire.data(), wire.size(), consumed);
  };
  assert(feedMap(maps, json) == MapMessages<1024>::Result::Ready);
  const auto smallCapacity = maps.allocated_capacity();
  const char *smallStorage = maps.data();
  assert(smallCapacity <= 512 && maps.size() == json.size());
  assert(feedMap(maps, json) == MapMessages<1024>::Result::Ready &&
         maps.data() == smallStorage);
  assert(feedMap(maps, std::string(600, 'x')) ==
         MapMessages<1024>::Result::Ready);
  const char *grownStorage = maps.data();
  assert(maps.allocated_capacity() >= 601 && maps.allocated_capacity() <= 1024);
  assert(feedMap(maps, json) == MapMessages<1024>::Result::Ready &&
         maps.data() == grownStorage);
  assert(feedMap(maps, std::string(1023, 'x')) ==
         MapMessages<1024>::Result::Ready);
  assert(feedMap(maps, std::string(1024, 'x')) ==
         MapMessages<1024>::Result::Invalid);
  maps.reset();
  assert(feedMap(maps, json) == MapMessages<1024>::Result::Ready);

  // Two legal maximum-size frames exceed 32 KiB; do not discard them.
  Fixture large;
  std::vector<uint8_t> block(16384, 42);
  dataFrame(large, block);
  dataFrame(large, block);
  assert(large.read_frame_(f, 1) && f.payload == block);
  assert(large.read_frame_(f, 1) && f.payload == block && large.pulls == 0);
  Fixture tooLarge;
  tooLarge.pending.resize(40961);
  assert(!tooLarge.pull_bytes_(1) && tooLarge.stream_failed() &&
         tooLarge.recv_buffer_.empty());

  auto finite = [&](const std::vector<uint8_t> &body, uint8_t flags = 1) {
    auto trial = std::make_unique<Fixture>();
    trial->recv_buffer_ = {0, 0, 1, 1, 4, 0, 0, 0, 5, 0x88};
    const auto n = body.size();
    trial->recv_buffer_.insert(
        trial->recv_buffer_.end(),
        {uint8_t(n >> 16), uint8_t(n >> 8), uint8_t(n), 0, flags, 0, 0, 0, 5});
    trial->recv_buffer_.insert(trial->recv_buffer_.end(), body.begin(),
                               body.end());
    return trial;
  };
  auto truncated = finite({'{'});
  assert(!truncated->post_json(5, "https", "example", "/map", "{}", result,
                               size, status, 10, true, false));
  assert(truncated->stream_failed());
  auto empty = finite({});
  assert(empty->post_json(5, "https", "example", "/map", "{}", result, size,
                          status, 10, true, false));
  assert(status == 200 && size == 0);
  auto padded = finite({1, '{', '}'}, 9);
  assert(!padded->post_json(5, "https", "example", "/map", "{}", result, size,
                            status, 10, true, false));
  auto noBody = std::make_unique<Fixture>();
  noBody->recv_buffer_ = {0, 0, 1, 1, 5, 0, 0, 0, 5, 0x88};
  assert(noBody->post_json(5, "https", "example", "/map", "{}", result, size,
                           status, 10, true, false) &&
         size == 0);
  assert(Fixture::has_complete_json_("{}", 2));
  const std::string trailing = "{}" + std::string(1500, ' ') + "x";
  assert(!Fixture::has_complete_json_(trailing.data(), trailing.size()));
  assert(!Fixture::has_complete_json_("{\"x\":\"broken}", 13));
  // Oversized full bodies fail instead of returning a silently truncated
  // prefix.
  Fixture overflow;
  overflow.recv_buffer_ = {0, 0, 1, 1, 4, 0, 0, 0, 5, 0x88};
  unsigned calls = 0;
  overflow.recv_cb_ = [&](std::vector<uint8_t> &out, uint32_t) {
    if (calls == 4)
      return false;
    out = {0, 64, 0, 0, uint8_t(calls == 3), 0, 0, 0, 5};
    out.resize(9 + 16384, ' ');
    if (calls++ == 0)
      out[9] = '{';
    return true;
  };
  assert(!overflow.post_json(5, "https", "example", "/map", "{}", result, size,
                             status, 10, true, false));
  assert(overflow.stream_failed());

  // A complete object followed by junk in another DATA frame is not complete.
  auto trailingData = finite({'{', '}'}, 0);
  trailingData->recv_buffer_.insert(trailingData->recv_buffer_.end(),
                                    {0, 0, 1, 0, 1, 0, 0, 0, 5, 'x'});
  assert(!trailingData->post_json(5, "https", "example", "/map", "{}", result,
                                  size, status, 10, true, false));
  assert(trailingData->stream_failed());
  Fixture badStream;
  Frame unexpected;
  unexpected.stream_id = 11;
  assert(!badStream.defer_frame_(std::move(unexpected)) &&
         badStream.stream_failed());
  assert(!badStream.post_json(5, "https", "example", "/map", "{}", result, size,
                              status, 10, true, false));
}
