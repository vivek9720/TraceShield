#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace traceshield::core {

struct SecurityTerm {
    const char* token;
    const char* category;
    int weight;
};

std::string protocol_name(std::uint8_t protocol);
std::string ethernet_type_name(std::uint16_t ether_type);
std::string service_name(std::uint16_t port, const std::string& protocol);
std::vector<SecurityTerm> security_terms();
int security_token_weight(const std::string& token);

}
