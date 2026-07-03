#include "core/endian.hpp"

namespace traceshield::core {
std::uint16_t read_be16(const std::uint8_t* p) noexcept { return static_cast<std::uint16_t>((p[0] << 8) | p[1]); }
std::uint16_t read_le16(const std::uint8_t* p) noexcept { return static_cast<std::uint16_t>((p[1] << 8) | p[0]); }
std::uint32_t read_be32(const std::uint8_t* p) noexcept { return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) | (static_cast<std::uint32_t>(p[2]) << 8) | p[3]; }
std::uint32_t read_le32(const std::uint8_t* p) noexcept { return (static_cast<std::uint32_t>(p[3]) << 24) | (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[1]) << 8) | p[0]; }
void append_be16(std::vector<std::uint8_t>& out, std::uint16_t value) { out.push_back(static_cast<std::uint8_t>(value >> 8)); out.push_back(static_cast<std::uint8_t>(value)); }
void append_le16(std::vector<std::uint8_t>& out, std::uint16_t value) { out.push_back(static_cast<std::uint8_t>(value)); out.push_back(static_cast<std::uint8_t>(value >> 8)); }
void append_be32(std::vector<std::uint8_t>& out, std::uint32_t value) { out.push_back(static_cast<std::uint8_t>(value >> 24)); out.push_back(static_cast<std::uint8_t>(value >> 16)); out.push_back(static_cast<std::uint8_t>(value >> 8)); out.push_back(static_cast<std::uint8_t>(value)); }
void append_le32(std::vector<std::uint8_t>& out, std::uint32_t value) { out.push_back(static_cast<std::uint8_t>(value)); out.push_back(static_cast<std::uint8_t>(value >> 8)); out.push_back(static_cast<std::uint8_t>(value >> 16)); out.push_back(static_cast<std::uint8_t>(value >> 24)); }
}
