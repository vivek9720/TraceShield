#include "packet/packet.hpp"
#include <cassert>
#include <cstdint>
#include <vector>
int main() {
    std::vector<std::uint8_t> frame = {0,1,2,3,4,5,6,7,8,9,10,11,0x08,0x00,0x45,0,0,40,0,1,0,0,64,6,0,0,192,168,1,2,93,184,216,34,0x30,0x39,0,80,0,0,0,0,0,0,0,0,0x50,0x02,0x20,0,0,0,0,0};
    auto rec = traceshield::packet::parse_frame_bytes(frame);
    assert(rec.metadata.protocol == "tcp");
    assert(rec.metadata.src_ip == "192.168.1.2");
}
