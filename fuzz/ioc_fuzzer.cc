#include "ioc/ioc.hpp"
#include "packet/packet.hpp"
#include <cstddef>
#include <cstdint>
#include <string>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::string text(reinterpret_cast<const char*>(data), size);
    auto set = traceshield::ioc::parse_ioc_text(text);
    std::vector<traceshield::packet::PacketMetadata> md(1);
    md[0].src_ip = "10.1.2.3";
    md[0].dst_ip = "198.51.100.4";
    md[0].protocol = "udp";
    md[0].dst_port = 53;
    md[0].domains.push_back("example.com");
    auto matches = traceshield::ioc::match_iocs(set, md);
    (void)traceshield::ioc::summarize_matches(matches);
    return 0;
}
