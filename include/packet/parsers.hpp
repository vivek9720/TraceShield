#pragma once
#include "core/byte_view.hpp"
#include "packet/packet.hpp"

namespace traceshield::packet {
core::Result<EthernetFrame> parse_ethernet(core::ByteView view);
core::Result<IPv4Packet> parse_ipv4_packet(core::ByteView view, std::size_t offset, std::size_t available);
core::Result<TransportSegment> parse_transport(core::ByteView view, const IPv4Packet& ip);
core::Result<DnsMessage> parse_dns(core::ByteView view, std::size_t offset, std::size_t available);
std::string dns_type_name(std::uint16_t type);
std::string tcp_flags_string(std::uint8_t flags);
}
