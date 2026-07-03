#include "rules/ids_rule.hpp"
#include <cassert>
int main() {
    auto set = traceshield::rules::parse_rules_text("alert tcp any any -> 10.0.0.1 443 (msg:\"tls\"; sid:1001; rev:1; content:\"example.com\";)\n");
    assert(set.rules.size() == 1);
    assert(set.diagnostics.empty());
    auto n = traceshield::rules::normalize_rule(set.rules[0]);
    assert(n.find("sid") != std::string::npos);
}
