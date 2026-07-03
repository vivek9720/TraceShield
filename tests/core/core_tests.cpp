#include "core/ip.hpp"
#include "core/strings.hpp"
#include <cassert>
int main() {
    traceshield::core::IPv4Address ip;
    assert(traceshield::core::parse_ipv4("192.168.1.10", ip));
    assert(traceshield::core::is_private(ip));
    traceshield::core::CidrRange r;
    assert(traceshield::core::parse_cidr("192.168.1.0/24", r));
    assert(r.contains(ip));
    assert(traceshield::core::lower("AbC") == "abc");
}
