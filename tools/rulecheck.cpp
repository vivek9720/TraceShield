#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

static std::vector<unsigned char> read_binary(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    return std::vector<unsigned char>(std::istreambuf_iterator<char>(in), {});
}
static std::string read_text(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), {});
}
static int usage(const char* name, const char* args) {
    std::cerr << "usage: " << name << " " << args << "\n";
    return 2;
}

#include "rules/ids_rule.hpp"
int main(int argc, char** argv) {
    if (argc != 2) return usage(argv[0], "<ids-rule-file>");
    auto set = traceshield::rules::parse_rules_text(read_text(argv[1]));
    std::cout << traceshield::rules::summarize_rules(set);
    for (const auto& r : set.rules) std::cout << traceshield::rules::normalize_rule(r) << "\n";
    return set.diagnostics.empty() ? 0 : 1;
}
