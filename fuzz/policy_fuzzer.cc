#include "policy/policy.hpp"
#include "packet/packet.hpp"
#include <cstddef>
#include <cstdint>
#include <string>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::string text(reinterpret_cast<const char*>(data), size);
    auto policy = traceshield::policy::parse_policy_text(text);
    auto findings = traceshield::policy::analyze_policy(policy);
    traceshield::packet::PacketMetadata md;
    md.src_ip = "10.0.0.2";
    md.dst_ip = "203.0.113.7";
    md.protocol = "tcp";
    md.dst_port = 443;
    for (const auto& r : policy.rules) (void)traceshield::policy::firewall_rule_matches(r, md);
    (void)traceshield::policy::summarize_policy(policy, findings);
    return 0;
}
