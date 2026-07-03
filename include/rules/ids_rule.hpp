#pragma once
#include "packet/packet.hpp"
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace traceshield::rules {
struct Endpoint { std::string address = "any"; bool negated = false; };
struct PortSpec { std::string text = "any"; bool negated = false; };
struct IdsRule {
    std::string action;
    std::string protocol;
    Endpoint source;
    PortSpec source_port;
    std::string direction;
    Endpoint destination;
    PortSpec destination_port;
    std::map<std::string, std::vector<std::string>> options;
    std::size_t line = 0;
};
struct RuleSet {
    std::vector<IdsRule> rules;
    std::vector<std::string> diagnostics;
};
RuleSet parse_rules_text(const std::string& text);
std::vector<std::string> validate_rule(const IdsRule& rule);
std::string normalize_rule(const IdsRule& rule);
bool rule_matches_metadata(const IdsRule& rule, const packet::PacketMetadata& metadata);
std::string summarize_rules(const RuleSet& set);
}
