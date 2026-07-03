#include "policy/policy.hpp"
#include <cassert>
int main() {
    auto p = traceshield::policy::parse_policy_text("-A INPUT -p tcp -s 10.0.0.0/8 --dport 22 -j ACCEPT\n-A INPUT -p tcp -s 10.1.2.3 --dport 22 -j DROP\n");
    auto f = traceshield::policy::analyze_policy(p);
    assert(p.rules.size() == 2);
    assert(!f.empty());
}
