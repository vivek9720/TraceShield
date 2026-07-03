#include "rules/ids_rule.hpp"
#include "packet/packet.hpp"
#include <cstddef>
#include <cstdint>
#include <string>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::string text(reinterpret_cast<const char*>(data), size);
    auto set = traceshield::rules::parse_rules_text(text);
    traceshield::packet::PacketMetadata md;
    md.src_ip = "10.0.0.2";
    md.dst_ip = "203.0.113.7";
    md.protocol = "tcp";
    md.src_port = 49152;
    md.dst_port = 443;
    md.domains.push_back("example.com");
    for (const auto& r : set.rules) (void)traceshield::rules::rule_matches_metadata(r, md);
    (void)traceshield::rules::summarize_rules(set);
    return 0;
}
