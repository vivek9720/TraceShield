#pragma once
#include "packet/packet.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace traceshield::policy {
struct FirewallRule {
    std::string source_text;
    std::string style;
    std::string chain = "INPUT";
    std::string action = "ACCEPT";
    std::string protocol = "any";
    std::string source = "any";
    std::string destination = "any";
    std::string source_port = "any";
    std::string destination_port = "any";
    std::size_t line = 0;
};
struct PolicyFile {
    std::vector<FirewallRule> rules;
    std::vector<std::string> diagnostics;
};
struct PolicyFinding {
    std::size_t line = 0;
    std::string severity;
    std::string message;
};
PolicyFile parse_policy_text(const std::string& text);
std::vector<PolicyFinding> analyze_policy(const PolicyFile& policy);
bool firewall_rule_matches(const FirewallRule& rule, const packet::PacketMetadata& metadata);
std::string normalize_firewall_rule(const FirewallRule& rule);
std::string summarize_policy(const PolicyFile& policy, const std::vector<PolicyFinding>& findings);
}
