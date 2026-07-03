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

#include "ioc/ioc.hpp"
#include "packet/packet.hpp"
int main(int argc, char** argv) {
    if (argc != 3) return usage(argv[0], "<ioc-file> <pcap-or-frame>");
    auto iocs = traceshield::ioc::parse_ioc_text(read_text(argv[1]));
    auto cap = traceshield::packet::parse_pcap_bytes(read_binary(argv[2]));
    auto matches = traceshield::ioc::match_iocs(iocs, traceshield::packet::metadata_from_capture(cap));
    std::cout << traceshield::ioc::summarize_iocs(iocs);
    std::cout << traceshield::ioc::summarize_matches(matches);
    return matches.empty() ? 1 : 0;
}
