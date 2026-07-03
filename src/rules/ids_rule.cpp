#include "rules/ids_rule.hpp"
#include "core/ip.hpp"
#include "core/strings.hpp"
#include <algorithm>
#include <cctype>
#include <set>
#include <sstream>

namespace traceshield::rules {
static std::vector<std::string> lex_header(const std::string& text) {
    std::vector<std::string> out;
    std::string cur;
    bool quoted = false;
    for (char c : text) {
        if (c == '"') quoted = !quoted;
        if (!quoted && std::isspace(static_cast<unsigned char>(c))) { if (!cur.empty()) { out.push_back(cur); cur.clear(); } }
        else cur.push_back(c);
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}
static Endpoint endpoint_from(std::string text) {
    Endpoint e;
    text = core::trim(text);
    if (!text.empty() && text[0] == '!') { e.negated = true; text.erase(text.begin()); }
    e.address = core::lower(core::trim(text));
    return e;
}
static PortSpec port_from(std::string text) {
    PortSpec p;
    text = core::trim(text);
    if (!text.empty() && text[0] == '!') { p.negated = true; text.erase(text.begin()); }
    p.text = core::lower(core::trim(text));
    return p;
}
static std::map<std::string, std::vector<std::string>> parse_options(const std::string& text) {
    std::map<std::string, std::vector<std::string>> out;
    std::string cur;
    bool quoted = false;
    bool escaped = false;
    auto flush = [&] {
        auto item = core::trim(cur);
        cur.clear();
        if (item.empty()) return;
        auto colon = item.find(':');
        std::string key = colon == std::string::npos ? item : item.substr(0, colon);
        std::string value = colon == std::string::npos ? "" : item.substr(colon + 1);
        key = core::lower(core::trim(key));
        value = core::remove_quotes(core::trim(value));
        out[key].push_back(value);
    };
    for (char c : text) {
        if (escaped) { cur.push_back(c); escaped = false; continue; }
        if (c == '\\') { cur.push_back(c); escaped = true; continue; }
        if (c == '"') quoted = !quoted;
        if (!quoted && c == ';') flush(); else cur.push_back(c);
    }
    flush();
    return out;
}
RuleSet parse_rules_text(const std::string& text) {
    RuleSet set;
    auto lines = core::split_lines(text);
    for (std::size_t i = 0; i < lines.size(); ++i) {
        auto line = core::trim(lines[i]);
        if (line.empty() || line[0] == '#') continue;
        auto open = line.find('(');
        auto close = line.rfind(')');
        auto header = open == std::string::npos ? line : line.substr(0, open);
        auto tokens = lex_header(header);
        if (tokens.size() < 7) { set.diagnostics.push_back("line " + std::to_string(i + 1) + ": rule header needs action protocol source port direction destination port"); continue; }
        IdsRule r;
        r.line = i + 1;
        r.action = core::lower(tokens[0]);
        r.protocol = core::lower(tokens[1]);
        r.source = endpoint_from(tokens[2]);
        r.source_port = port_from(tokens[3]);
        r.direction = tokens[4];
        r.destination = endpoint_from(tokens[5]);
        r.destination_port = port_from(tokens[6]);
        if (open != std::string::npos && close != std::string::npos && close > open) r.options = parse_options(line.substr(open + 1, close - open - 1));
        auto problems = validate_rule(r);
        for (const auto& p : problems) set.diagnostics.push_back("line " + std::to_string(i + 1) + ": " + p);
        set.rules.push_back(r);
    }
    return set;
}
static bool valid_endpoint(const Endpoint& e) {
    if (e.address == "any" || e.address == "$home_net" || e.address == "$external_net") return true;
    core::IPv4Address ip;
    core::CidrRange cidr;
    return core::parse_ipv4(e.address, ip) || core::parse_cidr(e.address, cidr);
}
static bool valid_port(const PortSpec& p) {
    if (p.text == "any") return true;
    auto parts = core::split(p.text, ':');
    if (parts.size() > 2) return false;
    for (const auto& part : parts) if (!part.empty() && (!core::is_decimal(part) || std::stoi(part) > 65535)) return false;
    return true;
}
std::vector<std::string> validate_rule(const IdsRule& rule) {
    std::vector<std::string> out;
    static const std::set<std::string> actions = {"alert","log","pass","drop","reject"};
    static const std::set<std::string> protocols = {"tcp","udp","icmp","ip","http","dns","tls"};
    if (!actions.count(rule.action)) out.push_back("unsupported action " + rule.action);
    if (!protocols.count(rule.protocol)) out.push_back("unsupported protocol " + rule.protocol);
    if (!valid_endpoint(rule.source)) out.push_back("invalid source endpoint");
    if (!valid_endpoint(rule.destination)) out.push_back("invalid destination endpoint");
    if (!valid_port(rule.source_port)) out.push_back("invalid source port");
    if (!valid_port(rule.destination_port)) out.push_back("invalid destination port");
    if (rule.direction != "->" && rule.direction != "<>") out.push_back("invalid direction");
    auto sid = rule.options.find("sid");
    if (sid == rule.options.end() || sid->second.empty() || !core::is_decimal(sid->second.front())) out.push_back("missing numeric sid");
    auto rev = rule.options.find("rev");
    if (rev != rule.options.end() && !rev->second.empty() && !core::is_decimal(rev->second.front())) out.push_back("non-numeric rev");
    return out;
}
std::string normalize_rule(const IdsRule& rule) {
    std::ostringstream out;
    out << core::lower(rule.action) << " " << core::lower(rule.protocol) << " ";
    if (rule.source.negated) out << "!";
    out << core::lower(rule.source.address) << " ";
    if (rule.source_port.negated) out << "!";
    out << core::lower(rule.source_port.text) << " " << rule.direction << " ";
    if (rule.destination.negated) out << "!";
    out << core::lower(rule.destination.address) << " ";
    if (rule.destination_port.negated) out << "!";
    out << core::lower(rule.destination_port.text) << " (";
    bool first = true;
    for (const auto& kv : rule.options) for (const auto& v : kv.second) { if (!first) out << " "; first = false; out << kv.first << ":" << '"' << v << '"' << ";"; }
    out << ")";
    return out.str();
}
static bool port_match(const PortSpec& spec, std::uint16_t port) {
    bool match = false;
    if (spec.text == "any") match = true;
    else {
        auto parts = core::split(spec.text, ':');
        if (parts.size() == 1 && core::is_decimal(parts[0])) match = port == static_cast<std::uint16_t>(std::stoi(parts[0]));
        else if (parts.size() == 2) {
            int lo = parts[0].empty() ? 0 : std::stoi(parts[0]);
            int hi = parts[1].empty() ? 65535 : std::stoi(parts[1]);
            match = port >= lo && port <= hi;
        }
    }
    return spec.negated ? !match : match;
}
static bool endpoint_match(const Endpoint& ep, const std::string& ip_text) {
    bool match = false;
    if (ep.address == "any" || ep.address == "$home_net" || ep.address == "$external_net") match = true;
    else {
        core::IPv4Address observed, single;
        core::CidrRange cidr;
        if (core::parse_ipv4(ip_text, observed) && core::parse_ipv4(ep.address, single)) match = observed == single;
        else if (core::parse_ipv4(ip_text, observed) && core::parse_cidr(ep.address, cidr)) match = cidr.contains(observed);
    }
    return ep.negated ? !match : match;
}
bool rule_matches_metadata(const IdsRule& rule, const packet::PacketMetadata& m) {
    auto proto = core::lower(m.protocol);
    bool proto_match = rule.protocol == "ip" || rule.protocol == proto || (rule.protocol == "dns" && proto == "udp" && (m.src_port == 53 || m.dst_port == 53));
    if (!proto_match) return false;
    bool forward = endpoint_match(rule.source, m.src_ip) && endpoint_match(rule.destination, m.dst_ip) && port_match(rule.source_port, m.src_port) && port_match(rule.destination_port, m.dst_port);
    bool reverse = rule.direction == "<>" && endpoint_match(rule.source, m.dst_ip) && endpoint_match(rule.destination, m.src_ip) && port_match(rule.source_port, m.dst_port) && port_match(rule.destination_port, m.src_port);
    if (!forward && !reverse) return false;
    auto content = rule.options.find("content");
    if (content != rule.options.end() && !content->second.empty()) {
        std::string joined = core::lower(core::join(m.domains, " "));
        for (const auto& c : content->second) if (joined.find(core::lower(c)) != std::string::npos) return true;
        return false;
    }
    return true;
}
std::string summarize_rules(const RuleSet& set) {
    std::map<std::string, int> actions;
    std::map<std::string, int> protocols;
    for (const auto& r : set.rules) { actions[r.action]++; protocols[r.protocol]++; }
    std::ostringstream out;
    out << "rules=" << set.rules.size() << "\n";
    for (const auto& a : actions) out << "action." << a.first << "=" << a.second << "\n";
    for (const auto& p : protocols) out << "protocol." << p.first << "=" << p.second << "\n";
    out << "diagnostics=" << set.diagnostics.size() << "\n";
    for (const auto& d : set.diagnostics) out << d << "\n";
    return out.str();
}
}
