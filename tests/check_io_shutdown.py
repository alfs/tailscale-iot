#!/usr/bin/env python3
"""Exercise the actual IO stop implementation, including late and missing acknowledgement."""
from pathlib import Path
import os, subprocess, tempfile
root = Path(__file__).resolve().parents[1]
text = (root/'components/tailscale/tailscale.cpp').read_text()
a = text.index('bool TailscaleComponent::stop_io_task_() {')
b = text.index('\n}\n', a) + 3
method = text[a:b]
fixture = r'''
#include <atomic>
#include <cassert>
#include <cstddef>
#include <initializer_list>
static unsigned delays, ackAfter;
static std::atomic<bool>* exited;
static std::atomic<bool>* running;
#define pdMS_TO_TICKS(n) (n)
void vTaskDelay(unsigned ticks) {
  assert(ticks == 10); assert(!running->load());
  if (++delays == ackAfter) exited->store(true);
}
struct TailscaleComponent {
  void* io_task_handle_{nullptr};
  std::atomic<bool> io_task_running_{false}, io_task_exited_{true};
  bool stop_io_task_();
};
'''+method+r'''
int main() {
  TailscaleComponent component;
  running=&component.io_task_running_; exited=&component.io_task_exited_;
  assert(component.stop_io_task_()); assert(delays == 0);
  for (unsigned at : {1U, 100U, 200U}) {
    delays=0; ackAfter=at;
    component.io_task_handle_=&component;
    component.io_task_running_=true; component.io_task_exited_=false;
    assert(component.stop_io_task_());
    assert(delays == at && component.io_task_handle_ == nullptr);
  }
  delays=0; ackAfter=201;
  component.io_task_handle_=&component;
  component.io_task_running_=true; component.io_task_exited_=false;
  assert(!component.stop_io_task_());
  assert(delays == 200 && component.io_task_handle_ == &component);
  // Timeout preserves the live handle; a later acknowledgement permits cleanup.
  component.io_task_exited_=true;
  assert(component.stop_io_task_()); assert(component.io_task_handle_ == nullptr);
}
'''
with tempfile.TemporaryDirectory(prefix='tailscale-io-test-') as tmp:
    source=Path(tmp)/'test.cpp'; source.write_text(fixture)
    binary=Path(tmp)/'test'
    subprocess.run([os.environ.get('CXX','clang++'),'-std=c++17','-g','-fsanitize=address,undefined',str(source),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
print('Actual IO shutdown acknowledgement/timeout checks: ASan/UBSan passed')
