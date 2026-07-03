#include "packet/packet.hpp"
#include "packet/insights.hpp"
#include "packet/parsers.hpp"
#include "core/byte_view.hpp"
#include "core/security_catalog.hpp"
#include <algorithm>
#include <sstream>

namespace traceshield::packet {

static PacketRecord parse_record(core::ByteView frame, core::Timestamp ts, std::size_t original_length) {
    PacketRecord rec;
    rec.bytes = frame.copy(0, frame.size());
    rec.metadata.timestamp = ts;
    rec.metadata.captured_length = frame.size();
    rec.metadata.original_length = original_length;
    auto eth = parse_ethernet(frame);
    if (!eth) {
        rec.metadata.malformed = true;
        rec.diagnostics.push_back({core::Severity::error, "ethernet", eth.status().message, eth.status().offset});
        return rec;
    }
    rec.metadata.fields["src_mac"] = eth.value().source_mac;
    rec.metadata.fields["dst_mac"] = eth.value().destination_mac;
    rec.metadata.fields["ether_type"] = core::ethernet_type_name(eth.value().ether_type);
    if (eth.value().ether_type != 0x0800) {
        rec.metadata.protocol = core::ethernet_type_name(eth.value().ether_type);
        return rec;
    }
    auto ip = parse_ipv4_packet(frame, eth.value().payload_offset, frame.size() - eth.value().payload_offset);
    if (!ip) {
        rec.metadata.malformed = true;
        rec.diagnostics.push_back({core::Severity::error, "ipv4", ip.status().message, ip.status().offset});
        return rec;
    }
    rec.metadata.src_ip = ip.value().source;
    rec.metadata.dst_ip = ip.value().destination;
    rec.metadata.protocol = core::protocol_name(ip.value().protocol);
    rec.metadata.fields["ttl"] = std::to_string(ip.value().ttl);
    rec.metadata.fields["ip_checksum"] = ip.value().checksum_valid ? "valid" : "invalid";
    if (ip.value().fragmented) rec.metadata.tags.push_back("fragmented");
    auto tsport = parse_transport(frame, ip.value());
    if (!tsport) {
        rec.metadata.malformed = true;
        rec.diagnostics.push_back({core::Severity::error, "transport", tsport.status().message, tsport.status().offset});
        return rec;
    }
    rec.metadata.src_port = tsport.value().source_port;
    rec.metadata.dst_port = tsport.value().destination_port;
    if (ip.value().protocol == 6) rec.metadata.fields["tcp_flags"] = tcp_flags_string(tsport.value().tcp_flags);
    bool dns_port = (tsport.value().source_port == 53 || tsport.value().destination_port == 53);
    if (ip.value().protocol == 17 && dns_port && tsport.value().payload_length > 0) {
        auto dns = parse_dns(frame, tsport.value().payload_offset, tsport.value().payload_length);
        if (dns) {
            for (const auto& n : dns.value().names) if (!n.empty()) rec.metadata.domains.push_back(n);
            rec.metadata.fields["dns_id"] = std::to_string(dns.value().id);
            rec.metadata.fields["dns_kind"] = dns.value().query ? "query" : "response";
        } else {
            rec.diagnostics.push_back({core::Severity::warning, "dns", dns.status().message, dns.status().offset});
        }
    }
    return rec;
}

PacketRecord parse_frame_bytes(const std::vector<std::uint8_t>& bytes) {
    return parse_record(core::ByteView(bytes), core::Timestamp{}, bytes.size());
}

PacketCapture parse_pcap_bytes(const std::vector<std::uint8_t>& bytes) {
    PacketCapture cap;
    core::ByteView view(bytes);
    if (view.size() < 24) {
        cap.records.push_back(parse_frame_bytes(bytes));
        cap.diagnostics.push_back({core::Severity::warning, "pcap", "input shorter than pcap header; treated as raw frame", 0});
        return cap;
    }
    auto magic = view.le32(0).value();
    bool little = false;
    bool nanos = false;
    if (magic == 0xa1b2c3d4U) { little = true; nanos = false; }
    else if (magic == 0xd4c3b2a1U) { little = false; nanos = false; }
    else if (magic == 0xa1b23c4dU) { little = true; nanos = true; }
    else if (magic == 0x4d3cb2a1U) { little = false; nanos = true; }
    else {
        cap.records.push_back(parse_frame_bytes(bytes));
        cap.diagnostics.push_back({core::Severity::warning, "pcap", "unknown pcap magic; treated as raw frame", 0});
        return cap;
    }
    auto rd16 = [&](std::size_t off){ return little ? view.le16(off).value() : view.be16(off).value(); };
    auto rd32 = [&](std::size_t off){ return little ? view.le32(off).value() : view.be32(off).value(); };
    cap.pcap = true;
    auto linktype = rd32(20);
    if (linktype != 1) cap.diagnostics.push_back({core::Severity::warning, "pcap", "only ethernet linktype is decoded", 20});
    std::size_t pos = 24;
    std::size_t guard = 0;
    while (pos + 16 <= view.size() && guard++ < 100000) {
        auto sec = rd32(pos);
        auto frac = rd32(pos + 4);
        auto incl = rd32(pos + 8);
        auto orig = rd32(pos + 12);
        pos += 16;
        if (incl > view.size() - pos) {
            cap.diagnostics.push_back({core::Severity::error, "pcap", "packet record exceeds file length", pos});
            break;
        }
        auto byteslice = view.slice(pos, incl).value();
        cap.records.push_back(parse_record(byteslice, core::normalize_timestamp(sec, frac, nanos), orig));
        pos += incl;
    }
    if (pos != view.size()) cap.diagnostics.push_back({core::Severity::warning, "pcap", "trailing bytes after last packet", pos});
    return cap;
}

std::string summarize_packet(const PacketMetadata& m) {
    std::ostringstream out;
    out << core::format_timestamp(m.timestamp) << " " << (m.protocol.empty() ? "unknown" : m.protocol);
    if (!m.src_ip.empty() || !m.dst_ip.empty()) out << " " << m.src_ip << ":" << m.src_port << " -> " << m.dst_ip << ":" << m.dst_port;
    if (!m.domains.empty()) out << " dns=" << core::join(m.domains, ",");
    auto insights = evaluate_traffic_insights(m);
    if (!insights.empty()) {
        out << " insights=";
        for (std::size_t i = 0; i < insights.size(); ++i) {
            if (i) out << ",";
            out << insights[i].id;
        }
    }
    if (m.malformed) out << " malformed";
    return out.str();
}
std::string summarize_capture(const PacketCapture& capture) {
    std::ostringstream out;
    out << "packets=" << capture.records.size() << "\n";
    std::map<std::string, int> proto;
    for (const auto& r : capture.records) proto[r.metadata.protocol]++;
    for (const auto& p : proto) out << p.first << "=" << p.second << "\n";
    for (const auto& r : capture.records) out << summarize_packet(r.metadata) << "\n";
    return out.str();
}
std::vector<PacketMetadata> metadata_from_capture(const PacketCapture& capture) {
    std::vector<PacketMetadata> out;
    for (const auto& r : capture.records) out.push_back(r.metadata);
    return out;
}
}
