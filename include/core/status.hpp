#pragma once
#include <cstddef>
#include <string>
#include <vector>

namespace traceshield::core {

enum class Severity { info, warning, error };

struct Diagnostic {
    Severity severity = Severity::info;
    std::string code;
    std::string message;
    std::size_t offset = 0;
};

class Diagnostics {
public:
    void add(Severity severity, std::string code, std::string message, std::size_t offset = 0);
    void info(std::string code, std::string message, std::size_t offset = 0);
    void warn(std::string code, std::string message, std::size_t offset = 0);
    void error(std::string code, std::string message, std::size_t offset = 0);
    bool has_errors() const;
    bool empty() const noexcept;
    std::size_t size() const noexcept;
    const std::vector<Diagnostic>& entries() const noexcept;
    std::string summary() const;
private:
    std::vector<Diagnostic> entries_;
};

enum class StatusCode {
    ok,
    invalid_argument,
    truncated,
    unsupported,
    malformed,
    not_found,
    overflow
};

struct Status {
    StatusCode code = StatusCode::ok;
    std::string message;
    std::size_t offset = 0;
    explicit operator bool() const noexcept { return code == StatusCode::ok; }
};

Status ok();
Status fail(StatusCode code, std::string message, std::size_t offset = 0);
std::string to_string(StatusCode code);

}
