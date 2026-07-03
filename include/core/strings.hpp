#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace traceshield::core {
std::string trim(const std::string& text);
std::string lower(std::string text);
std::string upper(std::string text);
std::vector<std::string> split(const std::string& text, char delimiter);
std::vector<std::string> split_lines(const std::string& text);
bool starts_with(const std::string& text, const std::string& prefix);
bool ends_with(const std::string& text, const std::string& suffix);
bool iequals(const std::string& a, const std::string& b);
std::string collapse_spaces(const std::string& text);
std::string remove_quotes(const std::string& text);
bool is_hex_string(const std::string& text);
bool is_decimal(const std::string& text);
std::string printable_ascii(const std::string& text);
std::string join(const std::vector<std::string>& parts, const std::string& separator);
}
