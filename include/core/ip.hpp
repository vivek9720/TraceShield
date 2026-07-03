#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace traceshield::core {

struct IPv4Address {
    std::uint32_t value = 0;
    bool operator==(const IPv4Address& other) const noexcept { return value == other.value; }
    bool operator!=(const IPv4Address& other) const noexcept { return value != other.value; }
    bool operator<(const IPv4Address& other) const noexcept { return value < other.value; }
};

struct CidrRange {
    IPv4Address network{};
    std::uint8_t prefix = 32;
    bool contains(IPv4Address address) const noexcept;
    std::string str() const;
};

bool parse_ipv4(const std::string& text, IPv4Address& out);
bool parse_cidr(const std::string& text, CidrRange& out);
std::string ipv4_to_string(IPv4Address address);
std::uint32_t prefix_mask(std::uint8_t prefix);
bool is_private(IPv4Address address);
bool is_loopback(IPv4Address address);
bool is_link_local(IPv4Address address);
bool is_multicast(IPv4Address address);
bool is_documentation(IPv4Address address);
bool is_global_unicast(IPv4Address address);
std::vector<CidrRange> reserved_ipv4_ranges();
std::string address_classification(IPv4Address address);
}
