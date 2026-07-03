#include "ioc/ioc.hpp"
#include "core/security_catalog.hpp"
#include "core/strings.hpp"
#include <algorithm>
#include <cctype>
#include <map>
#include <regex>
#include <set>
#include <sstream>

namespace traceshield::ioc {
static bool looks_domain(const std::string& value) {
    auto v = core::lower(value);
    if (v.size() > 253 || v.find('.') == std::string::npos || v.find("..") != std::string::npos) return false;
    for (char c : v) if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '.')) return false;
    return v.front() != '.' && v.back() != '.';
}
static bool looks_hash(const std::string& value) {
    auto v = value;
    if (core::starts_with(core::lower(v), "sha256:")) v = v.substr(7);
    if (core::starts_with(core::lower(v), "sha1:")) v = v.substr(5);
    if (core::starts_with(core::lower(v), "md5:")) v = v.substr(4);
    return (v.size() == 32 || v.size() == 40 || v.size() == 64) && core::is_hex_string(v);
}
IocType detect_ioc_type(const std::string& value) {
    auto v = core::trim(value);
    core::IPv4Address ip;
    core::CidrRange cidr;
    if (core::parse_cidr(v, cidr)) return IocType::cidr;
    if (core::parse_ipv4(v, ip)) return IocType::ip;
    auto l = core::lower(v);
    if (core::starts_with(l, "http://") || core::starts_with(l, "https://")) return IocType::url;
    if (looks_hash(v)) return IocType::hash;
    if (looks_domain(v)) return IocType::domain;
    return IocType::unknown;
}
std::string ioc_type_name(IocType type) {
    switch (type) {
    case IocType::ip: return "ip";
    case IocType::cidr: return "cidr";
    case IocType::domain: return "domain";
    case IocType::url: return "url";
    case IocType::hash: return "hash";
    case IocType::unknown: return "unknown";
    }
    return "unknown";
}
static std::string normalize_domain(std::string v) {
    v = core::lower(core::trim(v));
    if (!v.empty() && v.back() == '.') v.pop_back();
    return v;
}
static std::string extract_url_host(const std::string& value) {
    auto l = core::lower(core::trim(value));
    auto scheme = l.find("://");
    auto start = scheme == std::string::npos ? 0 : scheme + 3;
    auto end = l.find_first_of("/:?#", start);
    return normalize_domain(l.substr(start, end == std::string::npos ? std::string::npos : end - start));
}
std::string normalize_value(IocType type, const std::string& value) {
    auto v = core::trim(value);
    if (type == IocType::domain) return normalize_domain(v);
    if (type == IocType::url) return core::lower(v);
    if (type == IocType::hash) {
        auto l = core::lower(v);
        if (core::starts_with(l, "sha256:")) return l.substr(7);
        if (core::starts_with(l, "sha1:")) return l.substr(5);
        if (core::starts_with(l, "md5:")) return l.substr(4);
        return l;
    }
    if (type == IocType::cidr) { core::CidrRange r; if (core::parse_cidr(v, r)) return r.str(); }
    if (type == IocType::ip) { core::IPv4Address ip; if (core::parse_ipv4(v, ip)) return core::ipv4_to_string(ip); }
    return v;
}
static std::vector<std::string> parse_record_fields(const std::string& line) {
    std::vector<std::string> fields;
    std::string cur;
    bool quoted = false;
    for (char c : line) {
        if (c == '"') { quoted = !quoted; continue; }
        if (!quoted && (c == ',' || c == ';' || c == '\t')) { fields.push_back(core::trim(cur)); cur.clear(); }
        else cur.push_back(c);
    }
    fields.push_back(core::trim(cur));
    return fields;
}
IocSet parse_ioc_text(const std::string& text) {
    IocSet set;
    std::set<std::string> seen;
    auto lines = core::split_lines(text);
    for (std::size_t i = 0; i < lines.size(); ++i) {
        auto line = core::trim(lines[i]);
        if (line.empty() || line[0] == '#') continue;
        auto hash = line.find(" #");
        if (hash != std::string::npos) line = core::trim(line.substr(0, hash));
        auto fields = parse_record_fields(line);
        if (fields.empty()) continue;
        Ioc entry;
        entry.line = i + 1;
        entry.value = fields[0];
        entry.type = detect_ioc_type(entry.value);
        entry.normalized = normalize_value(entry.type, entry.value);
        for (std::size_t f = 1; f < fields.size(); ++f) {
            auto low = core::lower(fields[f]);
            if (low == "allow" || low == "allowed" || low == "allowlist") entry.allow = true;
            else if (low == "block" || low == "blocked" || low == "blocklist") entry.allow = false;
            else if (low == "low" || low == "medium" || low == "high" || low == "critical") entry.severity = low;
            else if (core::is_decimal(low)) entry.confidence = std::max(0, std::min(100, std::stoi(low)));
        }
        if (entry.type == IocType::ip) core::parse_ipv4(entry.normalized, entry.ip);
        if (entry.type == IocType::cidr) core::parse_cidr(entry.normalized, entry.cidr);
        if (entry.type == IocType::unknown) set.diagnostics.push_back("line " + std::to_string(entry.line) + ": unrecognized indicator");
        auto key = ioc_type_name(entry.type) + ":" + entry.normalized;
        if (!seen.insert(key).second) set.duplicates.push_back(key);
        set.entries.push_back(entry);
    }
    return set;
}
static bool domain_matches(const std::string& indicator, const std::string& observed) {
    auto i = normalize_domain(indicator);
    auto o = normalize_domain(observed);
    return o == i || (o.size() > i.size() && core::ends_with(o, "." + i));
}
std::vector<Match> match_iocs(const IocSet& set, const std::vector<packet::PacketMetadata>& metadata) {
    std::vector<Match> matches;
    for (const auto& m : metadata) {
        core::IPv4Address src, dst;
        bool has_src = core::parse_ipv4(m.src_ip, src);
        bool has_dst = core::parse_ipv4(m.dst_ip, dst);
        for (const auto& i : set.entries) {
            if (i.allow) continue;
            if (i.type == IocType::ip && ((has_src && src == i.ip) || (has_dst && dst == i.ip))) {
                matches.push_back({i, m, has_src && src == i.ip ? "src_ip" : "dst_ip", "exact ip match"});
            } else if (i.type == IocType::cidr && ((has_src && i.cidr.contains(src)) || (has_dst && i.cidr.contains(dst)))) {
                matches.push_back({i, m, has_src && i.cidr.contains(src) ? "src_ip" : "dst_ip", "cidr containment"});
            } else if (i.type == IocType::domain || i.type == IocType::url) {
                auto domain = i.type == IocType::url ? extract_url_host(i.normalized) : i.normalized;
                for (const auto& d : m.domains) if (domain_matches(domain, d)) matches.push_back({i, m, "dns", "domain match"});
            }
        }
    }
    return matches;
}
std::string summarize_iocs(const IocSet& set) {
    std::map<std::string, int> counts;
    for (const auto& e : set.entries) counts[ioc_type_name(e.type)]++;
    std::ostringstream out;
    out << "indicators=" << set.entries.size() << "\n";
    for (const auto& c : counts) out << c.first << "=" << c.second << "\n";
    out << "duplicates=" << set.duplicates.size() << "\n";
    out << "diagnostics=" << set.diagnostics.size() << "\n";
    return out.str();
}
std::string summarize_matches(const std::vector<Match>& matches) {
    std::ostringstream out;
    out << "matches=" << matches.size() << "\n";
    for (const auto& m : matches) out << m.ioc.severity << " " << ioc_type_name(m.ioc.type) << " " << m.ioc.normalized << " " << m.field << " " << m.reason << "\n";
    return out.str();
}
}
