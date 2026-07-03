#pragma once
#include "core/status.hpp"
#include <utility>

namespace traceshield::core {

template <typename T>
class Result {
public:
    Result(T value) : value_(std::move(value)), status_(ok()), has_value_(true) {}
    Result(Status status) : value_(), status_(std::move(status)), has_value_(false) {}
    bool has_value() const noexcept { return has_value_; }
    explicit operator bool() const noexcept { return has_value_; }
    const T& value() const & { return value_; }
    T& value() & { return value_; }
    T&& value() && { return std::move(value_); }
    const Status& status() const noexcept { return status_; }
private:
    T value_{};
    Status status_{};
    bool has_value_ = false;
};

template <typename T>
Result<T> success(T value) { return Result<T>(std::move(value)); }

template <typename T>
Result<T> failure(Status status) { return Result<T>(std::move(status)); }

}
