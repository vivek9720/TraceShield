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

#include "packet/packet.hpp"
int main(int argc, char** argv) {
    if (argc != 2) return usage(argv[0], "<pcap-or-frame>");
    auto bytes = read_binary(argv[1]);
    if (bytes.empty()) { std::cerr << "input is empty or unreadable\n"; return 1; }
    auto cap = traceshield::packet::parse_pcap_bytes(bytes);
    std::cout << traceshield::packet::summarize_capture(cap);
    for (const auto& d : cap.diagnostics) std::cerr << d.code << ": " << d.message << "\n";
    return cap.diagnostics.empty() ? 0 : 1;
}
