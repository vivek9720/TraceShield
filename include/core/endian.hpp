#pragma once
#include <cstdint>
#include <vector>

namespace traceshield::core {
std::uint16_t read_be16(const std::uint8_t* p) noexcept;
std::uint16_t read_le16(const std::uint8_t* p) noexcept;
std::uint32_t read_be32(const std::uint8_t* p) noexcept;
std::uint32_t read_le32(const std::uint8_t* p) noexcept;
void append_be16(std::vector<std::uint8_t>& out, std::uint16_t value);
void append_le16(std::vector<std::uint8_t>& out, std::uint16_t value);
void append_be32(std::vector<std::uint8_t>& out, std::uint32_t value);
void append_le32(std::vector<std::uint8_t>& out, std::uint32_t value);
}
