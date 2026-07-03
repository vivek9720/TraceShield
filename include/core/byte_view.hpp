#pragma once
#include "core/result.hpp"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace traceshield::core {

class ByteView {
public:
    ByteView() = default;
    ByteView(const std::uint8_t* data, std::size_t size) : data_(data), size_(size) {}
    explicit ByteView(const std::vector<std::uint8_t>& data) : data_(data.data()), size_(data.size()) {}
    const std::uint8_t* data() const noexcept { return data_; }
    std::size_t size() const noexcept { return size_; }
    bool empty() const noexcept { return size_ == 0; }
    bool can_read(std::size_t offset, std::size_t length) const noexcept;
    Result<ByteView> slice(std::size_t offset, std::size_t length) const;
    Result<std::uint8_t> u8(std::size_t offset) const;
    Result<std::uint16_t> be16(std::size_t offset) const;
    Result<std::uint16_t> le16(std::size_t offset) const;
    Result<std::uint32_t> be32(std::size_t offset) const;
    Result<std::uint32_t> le32(std::size_t offset) const;
    std::vector<std::uint8_t> copy(std::size_t offset, std::size_t length) const;
    std::string ascii_lossy(std::size_t offset, std::size_t length) const;
private:
    const std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
};

class Cursor {
public:
    explicit Cursor(ByteView view) : view_(view) {}
    std::size_t offset() const noexcept { return offset_; }
    std::size_t remaining() const noexcept;
    bool can_read(std::size_t length) const noexcept;
    Result<ByteView> read_bytes(std::size_t length);
    Result<std::uint8_t> read_u8();
    Result<std::uint16_t> read_be16();
    Result<std::uint16_t> read_le16();
    Result<std::uint32_t> read_be32();
    Result<std::uint32_t> read_le32();
    void skip(std::size_t length);
private:
    ByteView view_;
    std::size_t offset_ = 0;
};

}
