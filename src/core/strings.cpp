#include "core/strings.hpp"
#include <algorithm>
#include <cctype>
#include <sstream>

namespace traceshield::core {
std::string trim(const std::string& text) {
    std::size_t first = 0;
    while (first < text.size() && std::isspace(static_cast<unsigned char>(text[first]))) ++first;
    std::size_t last = text.size();
    while (last > first && std::isspace(static_cast<unsigned char>(text[last - 1]))) --last;
    return text.substr(first, last - first);
}
std::string lower(std::string text) { std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); }); return text; }
std::string upper(std::string text) { std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c){ return static_cast<char>(std::toupper(c)); }); return text; }
std::vector<std::string> split(const std::string& text, char delimiter) {
    std::vector<std::string> out;
    std::string cur;
    std::istringstream in(text);
    while (std::getline(in, cur, delimiter)) out.push_back(cur);
    if (!text.empty() && text.back() == delimiter) out.emplace_back();
    return out;
}
std::vector<std::string> split_lines(const std::string& text) {
    auto out = split(text, '\n');
    for (auto& s : out) if (!s.empty() && s.back() == '\r') s.pop_back();
    return out;
}
bool starts_with(const std::string& text, const std::string& prefix) { return text.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), text.begin()); }
bool ends_with(const std::string& text, const std::string& suffix) { return text.size() >= suffix.size() && std::equal(suffix.rbegin(), suffix.rend(), text.rbegin()); }
bool iequals(const std::string& a, const std::string& b) { return lower(a) == lower(b); }
std::string collapse_spaces(const std::string& text) {
    std::string out;
    bool in_space = false;
    for (char c : text) {
        if (std::isspace(static_cast<unsigned char>(c))) {
            if (!in_space) out.push_back(' ');
            in_space = true;
        } else {
            out.push_back(c);
            in_space = false;
        }
    }
    return trim(out);
}
std::string remove_quotes(const std::string& text) {
    auto t = trim(text);
    if (t.size() >= 2 && ((t.front() == '"' && t.back() == '"') || (t.front() == '\'' && t.back() == '\''))) return t.substr(1, t.size() - 2);
    return t;
}
bool is_hex_string(const std::string& text) {
    if (text.empty()) return false;
    for (char c : text) if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    return true;
}
bool is_decimal(const std::string& text) {
    if (text.empty()) return false;
    for (char c : text) if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    return true;
}
std::string printable_ascii(const std::string& text) {
    std::string out;
    for (char c : text) out.push_back(c >= 32 && c < 127 ? c : '.');
    return out;
}
std::string join(const std::vector<std::string>& parts, const std::string& separator) {
    std::ostringstream out;
    for (std::size_t i = 0; i < parts.size(); ++i) { if (i) out << separator; out << parts[i]; }
    return out.str();
}
}
