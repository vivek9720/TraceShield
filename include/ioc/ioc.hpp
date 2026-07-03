#pragma once
#include "core/ip.hpp"
#include "packet/packet.hpp"
#include <map>
#include <string>
#include <vector>

namespace traceshield::ioc {
enum class IocType { ip, cidr, domain, url, hash, unknown };
struct Ioc {
    IocType type = IocType::unknown;
    std::string value;
    std::string normalized;
    std::string severity = "medium";
    int confidence = 50;
    bool allow = false;
    std::size_t line = 0;
    core::IPv4Address ip{};
    core::CidrRange cidr{};
};
struct IocSet {
    std::vector<Ioc> entries;
    std::vector<std::string> duplicates;
    std::vector<std::string> diagnostics;
};
struct Match {
    Ioc ioc;
    packet::PacketMetadata metadata;
    std::string field;
    std::string reason;
};
IocType detect_ioc_type(const std::string& value);
std::string ioc_type_name(IocType type);
std::string normalize_value(IocType type, const std::string& value);
IocSet parse_ioc_text(const std::string& text);
std::vector<Match> match_iocs(const IocSet& set, const std::vector<packet::PacketMetadata>& metadata);
std::string summarize_iocs(const IocSet& set);
std::string summarize_matches(const std::vector<Match>& matches);
}
