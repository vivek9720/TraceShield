#include "packet/packet.hpp"
#include <cstddef>
#include <cstdint>
#include <vector>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::vector<std::uint8_t> bytes(data, data + size);
    auto cap = traceshield::packet::parse_pcap_bytes(bytes);
    (void)traceshield::packet::summarize_capture(cap);
    return 0;
}
