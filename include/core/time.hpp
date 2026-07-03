#pragma once
#include <cstdint>
#include <string>

namespace traceshield::core {
struct Timestamp {
    std::int64_t seconds = 0;
    std::int32_t micros = 0;
};
Timestamp normalize_timestamp(std::int64_t seconds, std::int64_t fraction, bool nanoseconds);
std::string format_timestamp(Timestamp ts);
bool parse_iso8601_utc(const std::string& text, Timestamp& out);
}
