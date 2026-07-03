#include "core/time.hpp"
#include <iomanip>
#include <sstream>

namespace traceshield::core {
Timestamp normalize_timestamp(std::int64_t seconds, std::int64_t fraction, bool nanoseconds) {
    Timestamp ts;
    ts.seconds = seconds;
    ts.micros = static_cast<std::int32_t>(nanoseconds ? fraction / 1000 : fraction);
    if (ts.micros >= 1000000) { ts.seconds += ts.micros / 1000000; ts.micros %= 1000000; }
    if (ts.micros < 0) { auto borrow = (-ts.micros + 999999) / 1000000; ts.seconds -= borrow; ts.micros += static_cast<std::int32_t>(borrow * 1000000); }
    return ts;
}
std::string format_timestamp(Timestamp ts) {
    std::ostringstream out;
    out << ts.seconds << "." << std::setw(6) << std::setfill('0') << ts.micros;
    return out.str();
}
bool parse_iso8601_utc(const std::string& text, Timestamp& out) {
    if (text.size() < 20 || text[4] != '-' || text[7] != '-' || text[10] != 'T' || text[19] != 'Z') return false;
    int y = std::stoi(text.substr(0, 4));
    int m = std::stoi(text.substr(5, 2));
    int d = std::stoi(text.substr(8, 2));
    int hh = std::stoi(text.substr(11, 2));
    int mm = std::stoi(text.substr(14, 2));
    int ss = std::stoi(text.substr(17, 2));
    if (m < 1 || m > 12 || d < 1 || d > 31 || hh > 23 || mm > 59 || ss > 60) return false;
    std::int64_t days = static_cast<std::int64_t>(y - 1970) * 365 + (y - 1969) / 4 - (y - 1901) / 100 + (y - 1601) / 400;
    static const int mdays[] = {0,31,59,90,120,151,181,212,243,273,304,334};
    days += mdays[m - 1] + d - 1;
    bool leap = (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0));
    if (leap && m > 2) ++days;
    out = Timestamp{days * 86400 + hh * 3600 + mm * 60 + ss, 0};
    return true;
}
}
