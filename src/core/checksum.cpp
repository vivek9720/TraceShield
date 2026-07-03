#include "core/checksum.hpp"
#include <iomanip>
#include <sstream>

namespace traceshield::core {
std::uint16_t internet_checksum(ByteView bytes) {
    std::uint32_t sum = 0;
    for (std::size_t i = 0; i + 1 < bytes.size(); i += 2) sum += bytes.be16(i).value();
    if (bytes.size() & 1U) sum += static_cast<std::uint16_t>(bytes.data()[bytes.size() - 1] << 8);
    while (sum >> 16) sum = (sum & 0xffffU) + (sum >> 16);
    return static_cast<std::uint16_t>(~sum);
}
std::uint32_t fnv1a32(ByteView bytes) {
    std::uint32_t h = 2166136261u;
    for (std::size_t i = 0; i < bytes.size(); ++i) { h ^= bytes.data()[i]; h *= 16777619u; }
    return h;
}
std::string hex_encode(ByteView bytes) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < bytes.size(); ++i) out << std::setw(2) << static_cast<unsigned>(bytes.data()[i]);
    return out.str();
}
std::vector<std::uint8_t> hex_decode_lossy(const std::string& text) {
    std::vector<std::uint8_t> out;
    int hi = -1;
    for (char c : text) {
        int v = -1;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = 10 + c - 'a';
        else if (c >= 'A' && c <= 'F') v = 10 + c - 'A';
        else continue;
        if (hi < 0) hi = v; else { out.push_back(static_cast<std::uint8_t>((hi << 4) | v)); hi = -1; }
    }
    return out;
}
}
