#include "packet/parsers.hpp"
#include "core/checksum.hpp"
#include "core/ip.hpp"
#include "core/security_catalog.hpp"
#include "core/strings.hpp"
#include <iomanip>
#include <set>
#include <sstream>

namespace traceshield::packet {
static std::string mac_to_string(const std::uint8_t* p) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) { if (i) out << ":"; out << std::setw(2) << static_cast<unsigned>(p[i]); }
    return out.str();
}
core::Result<EthernetFrame> parse_ethernet(core::ByteView view) {
    if (!view.can_read(0, 14)) return core::failure<EthernetFrame>(core::fail(core::StatusCode::truncated, "ethernet frame is shorter than header"));
    EthernetFrame frame;
    frame.destination_mac = mac_to_string(view.data());
    frame.source_mac = mac_to_string(view.data() + 6);
    frame.ether_type = view.be16(12).value();
    frame.payload_offset = 14;
    if (frame.ether_type == 0x8100 && view.can_read(14, 4)) {
        frame.ether_type = view.be16(16).value();
        frame.payload_offset = 18;
    }
    return core::success(frame);
}
core::Result<IPv4Packet> parse_ipv4_packet(core::ByteView view, std::size_t offset, std::size_t available) {
    if (!view.can_read(offset, 20) || available < 20) return core::failure<IPv4Packet>(core::fail(core::StatusCode::truncated, "ipv4 header truncated", offset));
    auto first = view.u8(offset).value();
    auto version = first >> 4;
    auto ihl = static_cast<std::size_t>(first & 0x0f) * 4;
    if (version != 4 || ihl < 20) return core::failure<IPv4Packet>(core::fail(core::StatusCode::malformed, "invalid ipv4 version or header length", offset));
    if (!view.can_read(offset, ihl) || available < ihl) return core::failure<IPv4Packet>(core::fail(core::StatusCode::truncated, "ipv4 options truncated", offset));
    IPv4Packet ip;
    ip.header_length = ihl;
    ip.total_length = view.be16(offset + 2).value();
    ip.identification = view.be16(offset + 4).value();
    auto flags_frag = view.be16(offset + 6).value();
    ip.fragmented = (flags_frag & 0x3fffU) != 0 || (flags_frag & 0x2000U) != 0;
    ip.ttl = view.u8(offset + 8).value();
    ip.protocol = view.u8(offset + 9).value();
    core::IPv4Address src{view.be32(offset + 12).value()};
    core::IPv4Address dst{view.be32(offset + 16).value()};
    ip.source = core::ipv4_to_string(src);
    ip.destination = core::ipv4_to_string(dst);
    auto hdr = view.slice(offset, ihl).value();
    ip.checksum_valid = core::internet_checksum(hdr) == 0;
    auto bounded_total = ip.total_length >= ihl ? std::min<std::size_t>(ip.total_length, available) : available;
    ip.payload_offset = offset + ihl;
    ip.payload_length = bounded_total > ihl ? bounded_total - ihl : 0;
    return core::success(ip);
}
core::Result<TransportSegment> parse_transport(core::ByteView view, const IPv4Packet& ip) {
    TransportSegment ts;
    ts.protocol = core::protocol_name(ip.protocol);
    if (ip.protocol != 6 && ip.protocol != 17) return core::success(ts);
    if (!view.can_read(ip.payload_offset, ip.protocol == 6 ? 20 : 8)) return core::failure<TransportSegment>(core::fail(core::StatusCode::truncated, "transport header truncated", ip.payload_offset));
    ts.source_port = view.be16(ip.payload_offset).value();
    ts.destination_port = view.be16(ip.payload_offset + 2).value();
    if (ip.protocol == 17) {
        ts.payload_offset = ip.payload_offset + 8;
        auto udp_len = view.be16(ip.payload_offset + 4).value();
        ts.payload_length = udp_len >= 8 ? std::min<std::size_t>(udp_len - 8, ip.payload_length >= 8 ? ip.payload_length - 8 : 0) : 0;
    } else {
        auto data_offset = static_cast<std::size_t>(view.u8(ip.payload_offset + 12).value() >> 4) * 4;
        if (data_offset < 20 || data_offset > ip.payload_length) return core::failure<TransportSegment>(core::fail(core::StatusCode::malformed, "invalid tcp data offset", ip.payload_offset));
        ts.tcp_flags = view.u8(ip.payload_offset + 13).value();
        ts.payload_offset = ip.payload_offset + data_offset;
        ts.payload_length = ip.payload_length > data_offset ? ip.payload_length - data_offset : 0;
    }
    return core::success(ts);
}
static core::Result<std::string> parse_dns_name(core::ByteView view, std::size_t& offset, std::size_t limit, int depth) {
    if (depth > 12) return core::failure<std::string>(core::fail(core::StatusCode::malformed, "dns compression loop", offset));
    std::vector<std::string> labels;
    while (offset < limit) {
        auto len = view.u8(offset).value();
        if ((len & 0xc0U) == 0xc0U) {
            if (!view.can_read(offset, 2)) return core::failure<std::string>(core::fail(core::StatusCode::truncated, "dns pointer truncated", offset));
            auto ptr = view.be16(offset).value() & 0x3fffU;
            offset += 2;
            std::size_t po = ptr;
            auto suffix = parse_dns_name(view, po, view.size(), depth + 1);
            if (!suffix) return suffix;
            labels.push_back(suffix.value());
            break;
        }
        ++offset;
        if (len == 0) break;
        if (len > 63 || !view.can_read(offset, len) || offset + len > limit) return core::failure<std::string>(core::fail(core::StatusCode::malformed, "invalid dns label", offset));
        labels.push_back(core::lower(view.ascii_lossy(offset, len)));
        offset += len;
    }
    return core::success(core::join(labels, "."));
}
core::Result<DnsMessage> parse_dns(core::ByteView view, std::size_t offset, std::size_t available) {
    if (!view.can_read(offset, 12) || available < 12) return core::failure<DnsMessage>(core::fail(core::StatusCode::truncated, "dns header truncated", offset));
    DnsMessage msg;
    std::size_t limit = std::min(view.size(), offset + available);
    msg.id = view.be16(offset).value();
    auto flags = view.be16(offset + 2).value();
    msg.query = (flags & 0x8000U) == 0;
    msg.opcode = static_cast<std::uint8_t>((flags >> 11) & 0x0f);
    msg.rcode = static_cast<std::uint8_t>(flags & 0x0f);
    auto qd = view.be16(offset + 4).value();
    auto an = view.be16(offset + 6).value();
    std::size_t pos = offset + 12;
    for (std::uint16_t i = 0; i < qd && i < 64; ++i) {
        auto name = parse_dns_name(view, pos, limit, 0);
        if (!name) return core::failure<DnsMessage>(name.status());
        if (!view.can_read(pos, 4) || pos + 4 > limit) return core::failure<DnsMessage>(core::fail(core::StatusCode::truncated, "dns question truncated", pos));
        DnsQuestion q{name.value(), view.be16(pos).value(), view.be16(pos + 2).value()};
        pos += 4;
        msg.questions.push_back(q);
        if (!q.name.empty()) msg.names.push_back(q.name);
    }
    for (std::uint16_t i = 0; i < an && i < 64 && pos < limit; ++i) {
        auto name = parse_dns_name(view, pos, limit, 0);
        if (!name) break;
        if (!view.can_read(pos, 10) || pos + 10 > limit) break;
        auto rdlen = view.be16(pos + 8).value();
        pos += 10;
        if (!view.can_read(pos, rdlen) || pos + rdlen > limit) break;
        msg.names.push_back(name.value());
        pos += rdlen;
    }
    return core::success(msg);
}
std::string dns_type_name(std::uint16_t type) {
    switch (type) {
    case 1: return "A";
    case 2: return "NS";
    case 5: return "CNAME";
    case 6: return "SOA";
    case 12: return "PTR";
    case 15: return "MX";
    case 16: return "TXT";
    case 28: return "AAAA";
    case 33: return "SRV";
    case 255: return "ANY";
    default: return "TYPE" + std::to_string(type);
    }
}
std::string tcp_flags_string(std::uint8_t flags) {
    std::vector<std::string> out;
    if (flags & 0x01) out.push_back("FIN");
    if (flags & 0x02) out.push_back("SYN");
    if (flags & 0x04) out.push_back("RST");
    if (flags & 0x08) out.push_back("PSH");
    if (flags & 0x10) out.push_back("ACK");
    if (flags & 0x20) out.push_back("URG");
    if (flags & 0x40) out.push_back("ECE");
    if (flags & 0x80) out.push_back("CWR");
    return out.empty() ? "none" : core::join(out, ",");
}
}
