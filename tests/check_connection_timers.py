#!/usr/bin/env python3
"""Compile the actual endpoint timer block against actual per-client fields."""
from pathlib import Path
import os
import re
import subprocess
import tempfile
root = Path(__file__).resolve().parents[1]
cpp = (root/'components/tailscale/tailscale.cpp').read_text()
header = (root/'components/tailscale/tailscale.h').read_text()
a = cpp.index('  // Send periodic endpoint updates every 60 seconds')
b = cpp.index('  // KEEPALIVE MODE:', a)
body = cpp[a:b]
a = header.index('  // Per-client state;')
b = header.index('  // NVS key persistence', a)
fields = header[a:b]
assert not re.search(r'\bstatic\b', body)
fixture = r'''
#include <cassert>
#include <cstdint>
static uint32_t clockMs;
uint32_t millis() { return clockMs; }
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGW(...) ((void)0)
#define ESP_LOGD(...) ((void)0)
struct Client {
'''+fields+r'''
  unsigned sends = 0;
  bool succeeds = true;
  bool send_map_keepalive_() { ++sends; return succeeds; }
  void tick() {
'''+body+r'''
  }
};
int main() {
  Client old;
  clockMs = 100000;
  old.tick(); assert(old.sends == 0);
  clockMs += 59999; old.tick(); assert(old.sends == 0);
  ++clockMs; old.tick(); assert(old.sends == 1);
  // Reconstruct at high uptime: first endpoint refresh still waits a full minute.
  Client fresh;
  clockMs += 70000; fresh.tick(); assert(fresh.sends == 0);
  clockMs += 60000; fresh.succeeds = false; fresh.tick(); assert(fresh.sends == 1);
  ++clockMs; fresh.tick(); assert(fresh.sends == 1); // no failed-update retry storm
  clockMs += 60000; fresh.tick(); assert(fresh.sends == 2);
  // A new network/client does not inherit relay backoff or NAT mapping success.
  old.derp_backoff_until = clockMs + 100000;
  old.derp_consecutive_failures = 8;
  old.natpmp_success = old.natpmp_requested = true;
  Client another;
  assert(!another.derp_backoff_until && !another.derp_consecutive_failures);
  assert(!another.natpmp_success && !another.natpmp_requested);
  Client wrapping;
  clockMs = UINT32_MAX - 10000; wrapping.tick();
  clockMs += 60000; wrapping.tick(); assert(wrapping.sends == 1);
}
'''
with tempfile.TemporaryDirectory(prefix='tailscale-timer-test-') as tmp:
    source = Path(tmp)/'test.cpp'; source.write_text(fixture)
    binary = Path(tmp)/'test'
    subprocess.run([os.environ.get('CXX', 'clang++'), '-std=c++17', '-fsanitize=address,undefined',
                    str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print('Actual connection timer block: reconstruction/retry/wrap checks passed')
