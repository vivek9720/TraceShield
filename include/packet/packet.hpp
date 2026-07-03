#pragma once
#include "core/status.hpp"
#include "core/time.hpp"
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace traceshield::packet {

struct EthernetFrame {
    std::string source_mac;
    std::string destination_mac;
    std::uint16_t ether_type = 0;
    std::size_t payload_offset = 0;
};

struct IPv4Packet {
    std::string source;
    std::string destination;
    std::uint8_t protocol = 0;
    std::uint8_t ttl = 0;
    std::uint16_t total_length = 0;
    std::uint16_t identification = 0;
    bool fragmented = false;
    std::size_t header_length = 0;
    std::size_t payload_offset = 0;
    std::size_t payload_length = 0;
    bool checksum_valid = false;
};

struct TransportSegment {
    std::string protocol;
    std::uint16_t source_port = 0;
    std::uint16_t destination_port = 0;
    std::uint8_t tcp_flags = 0;
    std::size_t payload_offset = 0;
    std::size_t payload_length = 0;
};

struct DnsQuestion {
    std::string name;
    std::uint16_t type = 0;
    std::uint16_t klass = 0;
};

struct DnsMessage {
    std::uint16_t id = 0;
    bool query = true;
    std::uint8_t opcode = 0;
    std::uint8_t rcode = 0;
    std::vector<DnsQuestion> questions;
    std::vector<std::string> names;
};

struct PacketMetadata {
    core::Timestamp timestamp{};
    std::size_t original_length = 0;
    std::size_t captured_length = 0;
    std::string src_ip;
    std::string dst_ip;
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    std::string protocol;
    std::vector<std::string> domains;
    std::vector<std::string> tags;
    bool malformed = false;
    std::map<std::string, std::string> fields;
};

struct PacketRecord {
    PacketMetadata metadata;
    std::vector<std::uint8_t> bytes;
    std::vector<core::Diagnostic> diagnostics;
};

struct PacketCapture {
    std::vector<PacketRecord> records;
    std::vector<core::Diagnostic> diagnostics;
    bool pcap = false;
};

PacketCapture parse_pcap_bytes(const std::vector<std::uint8_t>& bytes);
PacketRecord parse_frame_bytes(const std::vector<std::uint8_t>& bytes);
std::string summarize_packet(const PacketMetadata& metadata);
std::string summarize_capture(const PacketCapture& capture);
std::vector<PacketMetadata> metadata_from_capture(const PacketCapture& capture);

}
