#pragma once
#include "core/byte_view.hpp"
#include <cstdint>
#include <vector>

namespace traceshield::core {
std::uint16_t internet_checksum(ByteView bytes);
std::uint32_t fnv1a32(ByteView bytes);
std::string hex_encode(ByteView bytes);
std::vector<std::uint8_t> hex_decode_lossy(const std::string& text);
}
