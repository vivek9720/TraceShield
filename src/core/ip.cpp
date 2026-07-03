#include "core/ip.hpp"
#include "core/strings.hpp"
#include <cstdlib>
#include <sstream>

namespace traceshield::core {
std::uint32_t prefix_mask(std::uint8_t prefix) {
    if (prefix == 0) return 0;
    if (prefix >= 32) return 0xffffffffu;
    return 0xffffffffu << (32 - prefix);
}
bool CidrRange::contains(IPv4Address address) const noexcept {
    auto mask = prefix_mask(prefix);
    return (address.value & mask) == (network.value & mask);
}
std::string CidrRange::str() const { return ipv4_to_string(network) + "/" + std::to_string(prefix); }
bool parse_ipv4(const std::string& text, IPv4Address& out) {
    auto parts = split(trim(text), '.');
    if (parts.size() != 4) return false;
    std::uint32_t value = 0;
    for (const auto& p : parts) {
        if (!is_decimal(p) || p.size() > 3) return false;
        int octet = std::stoi(p);
        if (octet < 0 || octet > 255) return false;
        value = (value << 8) | static_cast<std::uint32_t>(octet);
    }
    out.value = value;
    return true;
}
bool parse_cidr(const std::string& text, CidrRange& out) {
    auto parts = split(trim(text), '/');
    if (parts.size() != 2 || !is_decimal(parts[1])) return false;
    IPv4Address ip;
    int prefix = std::stoi(parts[1]);
    if (!parse_ipv4(parts[0], ip) || prefix < 0 || prefix > 32) return false;
    out.prefix = static_cast<std::uint8_t>(prefix);
    out.network.value = ip.value & prefix_mask(out.prefix);
    return true;
}
std::string ipv4_to_string(IPv4Address address) {
    std::ostringstream out;
    out << ((address.value >> 24) & 0xff) << "." << ((address.value >> 16) & 0xff) << "." << ((address.value >> 8) & 0xff) << "." << (address.value & 0xff);
    return out.str();
}
static bool in_range(IPv4Address a, const char* cidr) {
    CidrRange r;
    return parse_cidr(cidr, r) && r.contains(a);
}
bool is_private(IPv4Address address) { return in_range(address, "10.0.0.0/8") || in_range(address, "172.16.0.0/12") || in_range(address, "192.168.0.0/16"); }
bool is_loopback(IPv4Address address) { return in_range(address, "127.0.0.0/8"); }
bool is_link_local(IPv4Address address) { return in_range(address, "169.254.0.0/16"); }
bool is_multicast(IPv4Address address) { return in_range(address, "224.0.0.0/4"); }
bool is_documentation(IPv4Address address) { return in_range(address, "192.0.2.0/24") || in_range(address, "198.51.100.0/24") || in_range(address, "203.0.113.0/24"); }
bool is_global_unicast(IPv4Address address) { return !is_private(address) && !is_loopback(address) && !is_link_local(address) && !is_multicast(address) && !is_documentation(address); }
std::vector<CidrRange> reserved_ipv4_ranges() {
    const char* ranges[] = {"0.0.0.0/8","10.0.0.0/8","100.64.0.0/10","127.0.0.0/8","169.254.0.0/16","172.16.0.0/12","192.0.0.0/24","192.0.2.0/24","192.168.0.0/16","198.18.0.0/15","198.51.100.0/24","203.0.113.0/24","224.0.0.0/4","240.0.0.0/4"};
    std::vector<CidrRange> out;
    for (auto r : ranges) { CidrRange c; if (parse_cidr(r, c)) out.push_back(c); }
    return out;
}
std::string address_classification(IPv4Address address) {
    if (is_private(address)) return "private";
    if (is_loopback(address)) return "loopback";
    if (is_link_local(address)) return "link-local";
    if (is_multicast(address)) return "multicast";
    if (is_documentation(address)) return "documentation";
    return "global";
}
}
