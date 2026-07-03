#include "core/status.hpp"
#include <sstream>

namespace traceshield::core {

void Diagnostics::add(Severity severity, std::string code, std::string message, std::size_t offset) {
    entries_.push_back(Diagnostic{severity, std::move(code), std::move(message), offset});
}
void Diagnostics::info(std::string code, std::string message, std::size_t offset) { add(Severity::info, std::move(code), std::move(message), offset); }
void Diagnostics::warn(std::string code, std::string message, std::size_t offset) { add(Severity::warning, std::move(code), std::move(message), offset); }
void Diagnostics::error(std::string code, std::string message, std::size_t offset) { add(Severity::error, std::move(code), std::move(message), offset); }
bool Diagnostics::has_errors() const { for (const auto& e : entries_) if (e.severity == Severity::error) return true; return false; }
bool Diagnostics::empty() const noexcept { return entries_.empty(); }
std::size_t Diagnostics::size() const noexcept { return entries_.size(); }
const std::vector<Diagnostic>& Diagnostics::entries() const noexcept { return entries_; }
std::string Diagnostics::summary() const {
    std::ostringstream out;
    for (const auto& e : entries_) {
        out << to_string(e.severity == Severity::error ? StatusCode::malformed : StatusCode::ok) << ":" << e.code << "@" << e.offset << " " << e.message << "\n";
    }
    return out.str();
}

Status ok() { return Status{}; }
Status fail(StatusCode code, std::string message, std::size_t offset) { return Status{code, std::move(message), offset}; }
std::string to_string(StatusCode code) {
    switch (code) {
    case StatusCode::ok: return "ok";
    case StatusCode::invalid_argument: return "invalid_argument";
    case StatusCode::truncated: return "truncated";
    case StatusCode::unsupported: return "unsupported";
    case StatusCode::malformed: return "malformed";
    case StatusCode::not_found: return "not_found";
    case StatusCode::overflow: return "overflow";
    }
    return "unknown";
}

}
