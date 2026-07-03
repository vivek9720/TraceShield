#include "policy/policy.hpp"
#include "core/ip.hpp"
#include "core/strings.hpp"
#include <algorithm>
#include <cctype>
#include <map>
#include <set>
#include <sstream>

namespace traceshield::policy {
static std::vector<std::string> words(const std::string& line) {
    std::vector<std::string> out;
    std::string cur;
    bool quoted = false;
    for (char c : line) {
        if (c == '"' || c == '\'') { quoted = !quoted; continue; }
        if (!quoted && std::isspace(static_cast<unsigned char>(c))) { if (!cur.empty()) { out.push_back(cur); cur.clear(); } }
        else cur.push_back(c);
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}
static FirewallRule parse_iptables(const std::vector<std::string>& t, std::size_t line, const std::string& raw) {
    FirewallRule r;
    r.style = "iptables";
    r.line = line;
    r.source_text = raw;
    for (std::size_t i = 0; i < t.size(); ++i) {
        auto k = t[i];
        auto next = [&]() -> std::string { return i + 1 < t.size() ? t[++i] : ""; };
        if (k == "-A" || k == "-I") r.chain = core::upper(next());
        else if (k == "-p" || k == "--protocol") r.protocol = core::lower(next());
        else if (k == "-s" || k == "--source") r.source = core::lower(next());
        else if (k == "-d" || k == "--destination") r.destination = core::lower(next());
        else if (k == "--sport" || k == "--source-port") r.source_port = core::lower(next());
        else if (k == "--dport" || k == "--destination-port") r.destination_port = core::lower(next());
        else if (k == "-j" || k == "--jump") r.action = core::upper(next());
    }
    return r;
}
static FirewallRule parse_nftables(const std::vector<std::string>& t, std::size_t line, const std::string& raw) {
    FirewallRule r;
    r.style = "nftables";
    r.line = line;
    r.source_text = raw;
    for (std::size_t i = 0; i < t.size(); ++i) {
        auto w = core::lower(t[i]);
        if (w == "chain" && i + 1 < t.size()) r.chain = core::upper(t[++i]);
        else if ((w == "tcp" || w == "udp" || w == "icmp") && i + 2 < t.size()) {
            r.protocol = w;
            auto field = core::lower(t[++i]);
            auto val = core::lower(t[++i]);
            if (field == "dport") r.destination_port = val;
            else if (field == "sport") r.source_port = val;
        } else if ((w == "ip" || w == "ip6") && i + 2 < t.size()) {
            auto field = core::lower(t[++i]);
            auto val = core::lower(t[++i]);
            if (field == "saddr") r.source = val;
            else if (field == "daddr") r.destination = val;
        } else if (w == "accept" || w == "drop" || w == "reject") {
            r.action = core::upper(w);
        }
    }
    return r;
}
static FirewallRule parse_ini_policy(const std::vector<std::string>& fields, std::size_t line, const std::string& raw) {
    FirewallRule r;
    r.style = "keyvalue";
    r.line = line;
    r.source_text = raw;
    for (const auto& f : fields) {
        auto pos = f.find('=');
        if (pos == std::string::npos) continue;
        auto key = core::lower(core::trim(f.substr(0, pos)));
        auto val = core::trim(f.substr(pos + 1));
        if (key == "chain") r.chain = core::upper(val);
        else if (key == "action") r.action = core::upper(val);
        else if (key == "protocol") r.protocol = core::lower(val);
        else if (key == "src" || key == "source") r.source = core::lower(val);
        else if (key == "dst" || key == "destination") r.destination = core::lower(val);
        else if (key == "sport") r.source_port = core::lower(val);
        else if (key == "dport") r.destination_port = core::lower(val);
    }
    return r;
}
PolicyFile parse_policy_text(const std::string& text) {
    PolicyFile pf;
    auto ls = core::split_lines(text);
    for (std::size_t i = 0; i < ls.size(); ++i) {
        auto line = core::trim(ls[i]);
        if (line.empty() || line[0] == '#') continue;
        auto t = words(line);
        if (t.empty()) continue;
        FirewallRule r;
        if (t[0] == "-A" || t[0] == "-I" || t[0] == "iptables" || t[0] == "ip6tables") r = parse_iptables(t, i + 1, line);
        else if (core::lower(t[0]) == "nft" || line.find(" dport ") != std::string::npos || line.find(" saddr ") != std::string::npos) r = parse_nftables(t, i + 1, line);
        else if (line.find('=') != std::string::npos) r = parse_ini_policy(core::split(line, ','), i + 1, line);
        else { pf.diagnostics.push_back("line " + std::to_string(i + 1) + ": unsupported policy syntax"); continue; }
        pf.rules.push_back(r);
    }
    return pf;
}
static bool valid_addr(const std::string& a) {
    if (a == "any" || a == "0.0.0.0/0") return true;
    core::IPv4Address ip;
    core::CidrRange cidr;
    return core::parse_ipv4(a, ip) || core::parse_cidr(a, cidr);
}
static bool valid_port(const std::string& p) {
    if (p == "any") return true;
    auto parts = core::split(p, ':');
    if (parts.size() > 2) return false;
    for (const auto& part : parts) if (!part.empty() && (!core::is_decimal(part) || std::stoi(part) > 65535)) return false;
    return true;
}
std::string normalize_firewall_rule(const FirewallRule& r) {
    std::ostringstream out;
    out << core::upper(r.chain) << " " << core::lower(r.protocol) << " " << core::lower(r.source) << ":" << r.source_port << " -> " << core::lower(r.destination) << ":" << r.destination_port << " " << core::upper(r.action);
    return out.str();
}
static bool covers_addr(const std::string& broader, const std::string& narrower) {
    if (broader == "any" || broader == "0.0.0.0/0") return true;
    if (broader == narrower) return true;
    core::CidrRange b, n;
    core::IPv4Address nip;
    if (core::parse_cidr(broader, b) && core::parse_ipv4(narrower, nip)) return b.contains(nip);
    if (core::parse_cidr(broader, b) && core::parse_cidr(narrower, n)) return b.contains(n.network) && b.prefix <= n.prefix;
    return false;
}
static bool covers_port(const std::string& broader, const std::string& narrower) {
    if (broader == "any" || broader == narrower) return true;
    auto range = [](const std::string& p){ auto v = core::split(p, ':'); if (v.size() == 2) return std::pair<int,int>{v[0].empty()?0:std::stoi(v[0]), v[1].empty()?65535:std::stoi(v[1])}; if (core::is_decimal(p)) { int n = std::stoi(p); return std::pair<int,int>{n,n}; } return std::pair<int,int>{-1,-1}; };
    auto b = range(broader);
    auto n = range(narrower);
    return b.first >= 0 && n.first >= 0 && b.first <= n.first && b.second >= n.second;
}
static bool shadows(const FirewallRule& a, const FirewallRule& b) {
    if (core::upper(a.chain) != core::upper(b.chain)) return false;
    if (a.protocol != "any" && a.protocol != b.protocol) return false;
    return covers_addr(a.source, b.source) && covers_addr(a.destination, b.destination) && covers_port(a.source_port, b.source_port) && covers_port(a.destination_port, b.destination_port);
}
std::vector<PolicyFinding> analyze_policy(const PolicyFile& policy) {
    std::vector<PolicyFinding> out;
    std::set<std::string> seen;
    for (std::size_t i = 0; i < policy.rules.size(); ++i) {
        const auto& r = policy.rules[i];
        auto norm = normalize_firewall_rule(r);
        if (!seen.insert(norm).second) out.push_back({r.line, "medium", "duplicate firewall rule"});
        if (!valid_addr(r.source)) out.push_back({r.line, "high", "invalid source address"});
        if (!valid_addr(r.destination)) out.push_back({r.line, "high", "invalid destination address"});
        if (!valid_port(r.source_port)) out.push_back({r.line, "high", "invalid source port"});
        if (!valid_port(r.destination_port)) out.push_back({r.line, "high", "invalid destination port"});
        if (r.action != "ACCEPT" && r.action != "DROP" && r.action != "REJECT" && r.action != "LOG") out.push_back({r.line, "medium", "unusual action " + r.action});
        for (std::size_t j = 0; j < i; ++j) {
            if (shadows(policy.rules[j], r)) {
                out.push_back({r.line, policy.rules[j].action == r.action ? "low" : "high", "rule shadowed by line " + std::to_string(policy.rules[j].line)});
                break;
            }
        }
    }
    for (const auto& d : policy.diagnostics) out.push_back({0, "medium", d});
    return out;
}
static bool match_addr(const std::string& rule_addr, const std::string& observed) {
    if (rule_addr == "any" || rule_addr == "0.0.0.0/0") return true;
    core::IPv4Address ip, single;
    core::CidrRange cidr;
    if (!core::parse_ipv4(observed, ip)) return false;
    if (core::parse_ipv4(rule_addr, single)) return ip == single;
    if (core::parse_cidr(rule_addr, cidr)) return cidr.contains(ip);
    return false;
}
static bool match_port(const std::string& spec, std::uint16_t port) { return covers_port(spec, std::to_string(port)); }
bool firewall_rule_matches(const FirewallRule& r, const packet::PacketMetadata& m) {
    if (r.protocol != "any" && r.protocol != core::lower(m.protocol)) return false;
    return match_addr(r.source, m.src_ip) && match_addr(r.destination, m.dst_ip) && match_port(r.source_port, m.src_port) && match_port(r.destination_port, m.dst_port);
}
std::string summarize_policy(const PolicyFile& policy, const std::vector<PolicyFinding>& findings) {
    std::map<std::string, int> actions;
    for (const auto& r : policy.rules) actions[r.action]++;
    std::ostringstream out;
    out << "rules=" << policy.rules.size() << "\n";
    for (const auto& a : actions) out << "action." << a.first << "=" << a.second << "\n";
    out << "findings=" << findings.size() << "\n";
    for (const auto& f : findings) out << f.severity << " line=" << f.line << " " << f.message << "\n";
    return out.str();
}
}
