#!/usr/bin/env python3
"""Test the actual manager and pinned WireGuard engine with real crypto.

Requires host libsodium through pkg-config. ESP/lwIP declarations and timing are
stubbed; handshakes, key derivation, packet authentication and manager routing
use the actual dependency sources. No real credentials are loaded.
"""
from pathlib import Path
import subprocess, shlex, argparse
args=argparse.ArgumentParser(description=__doc__)
args.add_argument('--wireguard-source',type=Path,required=True,help='Pinned esp_wireguard 0.4.2 src directory')
a=args.parse_args()
root=Path(__file__).resolve().parents[1]
out=root/'tests/.host-build/wireguard-crypto';out.mkdir(exist_ok=True,parents=True)
st=out/'stubs';st.mkdir(exist_ok=True)
stubs={
'lwip/netif.h':'#pragma once\nstruct netif;\n',
'lwip/udp.h':'#pragma once\nstruct udp_pcb;\n',
'lwip/ip_addr.h':'#pragma once\n#include <stdint.h>\ntypedef struct {uint32_t addr;} ip_addr_t;\n',
'lwip/arch.h':'#pragma once\n#include <stdint.h>\ntypedef uint16_t u16_t;\n',
'esp_err.h':'#pragma once\ntypedef int esp_err_t;\n#define ESP_OK 0\n',
'esp_log.h':'#pragma once\n#define ESP_LOGE(...)\n#define ESP_LOGW(...)\n#define ESP_LOGD(...)\n#define ESP_LOGI(...)\n#define ESP_LOGV(...)\n#define LOG_INF(...)\n#define LOG_ERR(...)\n',
'esp_random.h':'#pragma once\n#include <stdint.h>\nuint32_t esp_random();\n',
'esphome/core/log.h':'#include "esp_log.h"\n',
'esphome/core/hal.h':'#pragma once\n#include <stdint.h>\nuint32_t millis();\n',
'esphome/core/application.h':'#pragma once\nnamespace esphome {struct TestApp { void feed_wdt(){} }; inline TestApp App;}\n'
}
for name,s in stubs.items():p=st/name;p.parent.mkdir(exist_ok=True,parents=True);p.write_text(s)
lib=a.wireguard_source.resolve();mgr=root/'components/tailscale'
fixture=r'''
#include "wireguard_device_manager.h"
#include <sodium.h>
#include <cassert>
#include <deque>
#include <vector>
#include <cstdio>
#include <new>
extern "C" {
#include "wireguard.h"
#include "crypto.h"
uint32_t fixture_time=1000;
uint32_t wireguard_sys_now() { return fixture_time; }
void wireguard_random_bytes(void* p,size_t n) {randombytes_buf(p,n);}
void wireguard_tai64n_now(uint8_t* p) {static uint64_t t=0; memset(p,0,12);++t;for(int i=0;i<8;++i)p[11-i]=t>>(i*8);}
bool wireguard_is_under_load(){return false;}
esp_err_t wireguard_platform_init(){return 0;}
}
uint32_t millis(){return fixture_time;}
uint32_t esp_random(){uint32_t n;randombytes_buf(&n,sizeof n);return n;}
using esphome::tailscale::WireGuardDeviceManager;
struct Packet {int src,dst;std::vector<uint8_t> data;};
struct InspectedManager : WireGuardDeviceManager {
 size_t receiverRoutes() const {return receiver_to_peer_.size();}
 static size_t payloadLimit() {return MAX_IP_PACKET_SIZE;}
};
int main(){
 assert(sodium_init()>=0); InspectedManager m[3];uint8_t sk[3][32],pk[3][32];std::deque<Packet> q;
 for(int i=0;i<3;++i){randombytes_buf(sk[i],32);assert(!crypto_scalarmult_curve25519_base(pk[i],sk[i]));assert(m[i].init(sk[i]));}
 for(int i=0;i<3;++i){
  for(int j=0;j<3;++j)if(i!=j)assert(m[i].add_peer(std::to_string(j),pk[j]));
  m[i].set_send_callback([&,i](const std::string& dst,const uint8_t* p,size_t n){q.push_back({i,std::stoi(dst),{p,p+n}});});
 }
 auto drain=[&](bool allowOldData=false){int count=0;while(!q.empty()){assert(++count<200);auto p=std::move(q.front());q.pop_front();bool ok=m[p.dst].receive_wg_packet(p.data.data(),p.data.size());if(!ok)printf("Rejected type %u %d -> %d\n",p.data[0],p.src,p.dst);if(!ok&&allowOldData&&p.data[0]==4)continue;assert(ok);}};
 // Registering multiple keys must not break independent authenticated sessions.
 assert(m[0].start_peer_handshake("1"));assert(m[0].start_peer_handshake("2"));drain();
 int deliveries=0;for(int i=1;i<3;++i)m[i].set_decrypt_callback([&](const std::string&,const uint8_t* p,size_t n){assert(n==32&&p[0]==0x45);++deliveries;});
 uint8_t ip[32]={0x45};assert(m[0].send_ip_packet("1",ip,32));assert(m[0].send_ip_packet("2",ip,32));drain();assert(deliveries==2);
 // Authenticated oversized input must be rejected before allocating plaintext.
 std::vector<uint8_t> oversizedPlain(((InspectedManager::payloadLimit()+15)&~size_t(15))+16,0);
 oversizedPlain[0]=0x45;
 std::vector<uint8_t> oversized(oversizedPlain.size()+32,0);oversized[0]=4;
 auto* sendKey=&m[0].get_peer("1")->curr_keypair;
 U32TO8_LITTLE(oversized.data()+4,sendKey->remote_index);
 U64TO8_LITTLE(oversized.data()+8,sendKey->sending_counter);
 wireguard_encrypt_packet(oversized.data()+16,oversizedPlain.data(),oversizedPlain.size(),sendKey);
 assert(!m[1].receive_wg_packet(oversized.data(),oversized.size()));assert(deliveries==2);
 // An incoming rekey for one peer must preserve another peer's live session.
 assert(m[1].start_peer_handshake("0"));drain();
 assert(m[0].send_ip_packet("2",ip,32));drain();assert(deliveries==3);
 // Cross counter boundaries and interleave peers with real authenticated data.
 for(int n=0;n<80;++n){assert(m[0].send_ip_packet("1",ip,32));assert(m[0].send_ip_packet("2",ip,32));drain();}
 assert(deliveries==163);
 // Independently authenticate native output using libsodium's RFC 8439 AEAD.
 assert(m[0].send_ip_packet("1",ip,32));assert(q.size()==1);
 uint8_t nonce[12]={};memcpy(nonce+4,q.front().data.data()+8,8);
 uint8_t plaintext[32];unsigned long long decoded=0;
 assert(!crypto_aead_chacha20poly1305_ietf_decrypt(plaintext,&decoded,nullptr,
     q.front().data.data()+16,q.front().data.size()-16,nullptr,0,nonce,
     m[0].get_peer("1")->curr_keypair.sending_key));
 assert(decoded==32&&!memcmp(plaintext,ip,32));
 auto corrupted=q.front().data;corrupted.back()^=1;
 assert(!m[1].receive_wg_packet(corrupted.data(),corrupted.size()));
 assert(crypto_aead_chacha20poly1305_ietf_decrypt(plaintext,&decoded,nullptr,
     corrupted.data()+16,corrupted.size()-16,nullptr,0,nonce,
     m[1].get_peer("0")->curr_keypair.receiving_key)!=0);
 drain();assert(deliveries==164);
 // Timed rollover must accept a delayed old-key packet exactly once, after
 // new-key traffic promotes the responder's next keypair. Interleave a second
 // peer whose key is still within the rejection window, then renew it too.
 for(int round=0;round<3;++round){
  const int beforeTimed=deliveries;
  assert(m[0].send_ip_packet("1",ip,32));assert(q.size()==1);
  auto delayed=std::move(q.front());q.pop_front();
  assert(m[0].send_ip_packet("2",ip,32));assert(q.size()==1);
  auto unrelated=std::move(q.front());q.pop_front();
  fixture_time+=(REKEY_AFTER_TIME+1)*1000;
  assert(wireguard_expired(m[0].get_peer("1")->curr_keypair.keypair_millis, REKEY_AFTER_TIME));
  assert(m[0].is_handshake_established("1"));
  assert(m[0].start_peer_handshake("1"));
  assert(m[0].is_handshake_established("1"));
  // Carry authenticated old-key traffic while the response is still pending.
  assert(m[0].send_ip_packet("1",ip,32));drain();
  assert(m[0].send_ip_packet("1",ip,32));drain();
  assert(m[1].receive_wg_packet(delayed.data.data(),delayed.data.size()));
  assert(!m[1].receive_wg_packet(delayed.data.data(),delayed.data.size()));
  assert(m[2].receive_wg_packet(unrelated.data.data(),unrelated.data.size()));
  assert(m[0].start_peer_handshake("2"));drain();
  assert(m[0].send_ip_packet("2",ip,32));drain();
  assert(deliveries==beforeTimed+5);
  assert(m[0].receiverRoutes()<=6); // At most current/previous/next for each of two peers.
 }
 // Removal must reject old receiver indexes after both handshake directions.
 assert(m[1].send_ip_packet("0",ip,32));assert(q.size()==1);
 auto stale=std::move(q.front());q.pop_front();
 m[0].remove_peer("1");
 assert(!m[0].receive_wg_packet(stale.data.data(),stale.data.size()));
 assert(m[0].send_ip_packet("2",ip,32));drain();assert(deliveries==180);
 assert(m[0].add_peer("1",pk[1]));
 // Reconstruct the reader with its persistent identity, then accept an
 // incoming initiation before it makes any outgoing application request.
 m[0].~InspectedManager();new (&m[0]) InspectedManager;
 assert(m[0].init(sk[0]));
 assert(m[0].add_peer("1",pk[1]));assert(m[0].add_peer("2",pk[2]));
 m[0].set_send_callback([&](const std::string& dst,const uint8_t* p,size_t n){q.push_back({0,std::stoi(dst),{p,p+n}});});
 assert(m[1].start_peer_handshake("0"));drain();
 int incoming=0;m[0].set_decrypt_callback([&](const std::string& src,const uint8_t* p,size_t n){assert(src=="1"&&n==32&&p[0]==0x45);++incoming;});
 assert(m[1].send_ip_packet("0",ip,32));drain();assert(incoming==1);
 // Renewal keeps traffic usable only before hard time/message rejection.
 auto* finalKey=&m[0].get_peer("1")->curr_keypair;
 const auto savedCounter=finalKey->sending_counter;
 finalKey->sending_counter=REKEY_AFTER_MESSAGES;
 assert(m[0].needs_rekey("1")&&m[0].is_handshake_established("1"));
 finalKey->sending_counter=REJECT_AFTER_MESSAGES;
 assert(!m[0].is_handshake_established("1"));
 assert(!m[0].send_ip_packet("1",ip,32));
 finalKey->sending_counter=savedCounter;
 fixture_time+=(REJECT_AFTER_TIME+1)*1000;
 assert(!m[0].is_handshake_established("1")&&m[0].needs_rekey("1"));
 assert(!m[0].send_ip_packet("1",ip,32));
 puts("Actual multi-peer crypto, timed renewal continuity, delayed-key replay rejection and hard expiry passed");
}
'''
f=out/'test.cpp';f.write_text(fixture)
sodium_flags=shlex.split(subprocess.check_output(['pkg-config','--cflags','--libs','libsodium'],text=True))
sodium_compile=shlex.split(subprocess.check_output(['pkg-config','--cflags','libsodium'],text=True))
flags=['-g','-fsanitize=address,undefined','-fno-omit-frame-pointer','-DCONFIG_WIREGUARD_MAX_PEERS=8','-I'+str(st),'-I'+str(lib),'-I'+str(mgr)]
objects=[]
for s in [lib/'wireguard.c',lib/'crypto.c',*sorted((lib/'crypto/refc').glob('*.c'))]:
 obj=out/(s.stem+'.o');subprocess.run(['clang','-std=c11',*flags,*sodium_compile,'-c',str(s),'-o',str(obj)],check=True);objects.append(str(obj))
b=out/'test';subprocess.run(['clang++','-std=c++17',*flags,str(f),str(mgr/'wireguard_device_manager.cpp'),*objects,*sodium_flags,'-o',str(b)],check=True)
subprocess.run([str(b)],check=True)
