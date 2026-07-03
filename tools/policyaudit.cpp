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

#include "policy/policy.hpp"
int main(int argc, char** argv) {
    if (argc != 2) return usage(argv[0], "<policy-file>");
    auto policy = traceshield::policy::parse_policy_text(read_text(argv[1]));
    auto findings = traceshield::policy::analyze_policy(policy);
    std::cout << traceshield::policy::summarize_policy(policy, findings);
    return findings.empty() ? 0 : 1;
}
