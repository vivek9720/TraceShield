#include "ioc/ioc.hpp"
#include <cassert>
int main() {
    auto set = traceshield::ioc::parse_ioc_text("1.2.3.4,high,90\nexample.com,medium\n10.0.0.0/8\nbad value here\n");
    assert(set.entries.size() == 4);
    assert(set.entries[0].type == traceshield::ioc::IocType::ip);
    assert(set.entries[2].type == traceshield::ioc::IocType::cidr);
    assert(!set.diagnostics.empty());
}
