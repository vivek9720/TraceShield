#include "core/byte_view.hpp"
#include "core/endian.hpp"
#include <algorithm>

namespace traceshield::core {

bool ByteView::can_read(std::size_t offset, std::size_t length) const noexcept {
    return offset <= size_ && length <= size_ - offset;
}
Result<ByteView> ByteView::slice(std::size_t offset, std::size_t length) const {
    if (!can_read(offset, length)) return failure<ByteView>(fail(StatusCode::truncated, "slice exceeds input", offset));
    return success(ByteView(data_ + offset, length));
}
Result<std::uint8_t> ByteView::u8(std::size_t offset) const {
    if (!can_read(offset, 1)) return failure<std::uint8_t>(fail(StatusCode::truncated, "missing byte", offset));
    return success(data_[offset]);
}
Result<std::uint16_t> ByteView::be16(std::size_t offset) const {
    if (!can_read(offset, 2)) return failure<std::uint16_t>(fail(StatusCode::truncated, "missing be16", offset));
    return success(read_be16(data_ + offset));
}
Result<std::uint16_t> ByteView::le16(std::size_t offset) const {
    if (!can_read(offset, 2)) return failure<std::uint16_t>(fail(StatusCode::truncated, "missing le16", offset));
    return success(read_le16(data_ + offset));
}
Result<std::uint32_t> ByteView::be32(std::size_t offset) const {
    if (!can_read(offset, 4)) return failure<std::uint32_t>(fail(StatusCode::truncated, "missing be32", offset));
    return success(read_be32(data_ + offset));
}
Result<std::uint32_t> ByteView::le32(std::size_t offset) const {
    if (!can_read(offset, 4)) return failure<std::uint32_t>(fail(StatusCode::truncated, "missing le32", offset));
    return success(read_le32(data_ + offset));
}
std::vector<std::uint8_t> ByteView::copy(std::size_t offset, std::size_t length) const {
    if (!can_read(offset, length)) return {};
    return std::vector<std::uint8_t>(data_ + offset, data_ + offset + length);
}
std::string ByteView::ascii_lossy(std::size_t offset, std::size_t length) const {
    if (!can_read(offset, length)) return {};
    std::string out;
    out.reserve(length);
    for (std::size_t i = 0; i < length; ++i) {
        auto c = data_[offset + i];
        out.push_back(c >= 32 && c < 127 ? static_cast<char>(c) : '.');
    }
    return out;
}
std::size_t Cursor::remaining() const noexcept { return offset_ <= view_.size() ? view_.size() - offset_ : 0; }
bool Cursor::can_read(std::size_t length) const noexcept { return view_.can_read(offset_, length); }
Result<ByteView> Cursor::read_bytes(std::size_t length) {
    auto r = view_.slice(offset_, length);
    if (r) offset_ += length;
    return r;
}
Result<std::uint8_t> Cursor::read_u8() { auto r = view_.u8(offset_); if (r) ++offset_; return r; }
Result<std::uint16_t> Cursor::read_be16() { auto r = view_.be16(offset_); if (r) offset_ += 2; return r; }
Result<std::uint16_t> Cursor::read_le16() { auto r = view_.le16(offset_); if (r) offset_ += 2; return r; }
Result<std::uint32_t> Cursor::read_be32() { auto r = view_.be32(offset_); if (r) offset_ += 4; return r; }
Result<std::uint32_t> Cursor::read_le32() { auto r = view_.le32(offset_); if (r) offset_ += 4; return r; }
void Cursor::skip(std::size_t length) { offset_ = std::min(view_.size(), offset_ + length); }

}
