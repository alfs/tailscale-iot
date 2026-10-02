#!/usr/bin/env python3
"""Exercise the actual removal block with previous/current/next receiver routes."""
from pathlib import Path
import subprocess
import tempfile
root=Path(__file__).resolve().parents[1]
s=(root/'components/tailscale/wireguard_device_manager.cpp').read_text()
a=s.index('void WireGuardDeviceManager::remove_peer(')
b=s.index('\n::wireguard_peer*',a)
method=s[a:b]
fixture=r'''#include <map>
#include <string>
#include <cassert>
#define ESP_LOGW(...)
#define ESP_LOGI(...)
struct Peer {bool valid=true;};
struct Context {Peer* peer;unsigned receiver_index;};
struct WireGuardDeviceManager {
 std::map<std::string,Context> peers_;
 std::map<unsigned,std::string> receiver_to_peer_;
 void remove_peer(const std::string&);
};
'''+method+r'''
int main(){
 WireGuardDeviceManager m;Peer a,b;
 m.peers_["a"]={&a,11};m.peers_["b"]={&b,99};
 m.receiver_to_peer_={{10,"a"},{11,"a"},{12,"a"},{99,"b"}};
 m.remove_peer("a");
 assert(!a.valid&&b.valid&&m.peers_.size()==1);
 assert(m.receiver_to_peer_.size()==1&&m.receiver_to_peer_[99]=="b");
 m.remove_peer("a");assert(m.receiver_to_peer_.size()==1);
 m.remove_peer("b");assert(!b.valid&&m.receiver_to_peer_.empty());
}
'''
with tempfile.TemporaryDirectory(prefix='peer-removal-') as tmp:
 p=Path(tmp)/'test.cpp';p.write_text(fixture);b=Path(tmp)/'test'
 subprocess.run(['clang++','-std=c++17','-fsanitize=address,undefined',str(p),'-o',str(b)],check=True)
 subprocess.run([str(b)],check=True)
print('Actual peer removal: all receiver routes cleared, other peer preserved')
