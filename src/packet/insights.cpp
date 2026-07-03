#include "packet/insights.hpp"
#include "core/strings.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace traceshield::packet {
struct TrafficHeuristic {
    const char* id;
    const char* protocol;
    std::uint16_t port;
    const char* side;
    const char* category;
    const char* severity;
    const char* description;
};
static const TrafficHeuristic kTrafficHeuristics[] = {
    {
        "tcp-ftp-ingress-exposed-service",
        "tcp",
        21,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ftp legacy-file-transfer on tcp/21 during ingress"
    },
    {
        "tcp-ftp-ingress-cleartext-risk",
        "tcp",
        21,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: ftp legacy-file-transfer on tcp/21 during ingress"
    },
    {
        "tcp-ftp-ingress-legacy-compat",
        "tcp",
        21,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ftp legacy-file-transfer on tcp/21 during ingress"
    },
    {
        "tcp-ftp-egress-exposed-service",
        "tcp",
        21,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ftp legacy-file-transfer on tcp/21 during egress"
    },
    {
        "tcp-ftp-egress-cleartext-risk",
        "tcp",
        21,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: ftp legacy-file-transfer on tcp/21 during egress"
    },
    {
        "tcp-ftp-egress-legacy-compat",
        "tcp",
        21,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ftp legacy-file-transfer on tcp/21 during egress"
    },
    {
        "tcp-ftp-source-service-exposed-service",
        "tcp",
        21,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: ftp legacy-file-transfer on tcp/21 during source-service"
    },
    {
        "tcp-ftp-source-service-cleartext-risk",
        "tcp",
        21,
        "src",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: ftp legacy-file-transfer on tcp/21 during source-service"
    },
    {
        "tcp-ftp-source-service-legacy-compat",
        "tcp",
        21,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ftp legacy-file-transfer on tcp/21 during source-service"
    },
    {
        "tcp-ftp-lateral-exposed-service",
        "tcp",
        21,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ftp legacy-file-transfer on tcp/21 during lateral"
    },
    {
        "tcp-ftp-lateral-cleartext-risk",
        "tcp",
        21,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: ftp legacy-file-transfer on tcp/21 during lateral"
    },
    {
        "tcp-ftp-lateral-legacy-compat",
        "tcp",
        21,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ftp legacy-file-transfer on tcp/21 during lateral"
    },
    {
        "tcp-ftp-inventory-exposed-service",
        "tcp",
        21,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ftp legacy-file-transfer on tcp/21 during inventory"
    },
    {
        "tcp-ftp-inventory-cleartext-risk",
        "tcp",
        21,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: ftp legacy-file-transfer on tcp/21 during inventory"
    },
    {
        "tcp-ftp-inventory-legacy-compat",
        "tcp",
        21,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ftp legacy-file-transfer on tcp/21 during inventory"
    },
    {
        "tcp-ftp-admin-plane-exposed-service",
        "tcp",
        21,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ftp legacy-file-transfer on tcp/21 during admin-plane"
    },
    {
        "tcp-ftp-admin-plane-cleartext-risk",
        "tcp",
        21,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: ftp legacy-file-transfer on tcp/21 during admin-plane"
    },
    {
        "tcp-ftp-admin-plane-legacy-compat",
        "tcp",
        21,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ftp legacy-file-transfer on tcp/21 during admin-plane"
    },
    {
        "tcp-ssh-ingress-exposed-service",
        "tcp",
        22,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ssh remote-admin on tcp/22 during ingress"
    },
    {
        "tcp-ssh-ingress-management-plane",
        "tcp",
        22,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: ssh remote-admin on tcp/22 during ingress"
    },
    {
        "tcp-ssh-ingress-legacy-compat",
        "tcp",
        22,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ssh remote-admin on tcp/22 during ingress"
    },
    {
        "tcp-ssh-egress-exposed-service",
        "tcp",
        22,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ssh remote-admin on tcp/22 during egress"
    },
    {
        "tcp-ssh-egress-management-plane",
        "tcp",
        22,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: ssh remote-admin on tcp/22 during egress"
    },
    {
        "tcp-ssh-egress-legacy-compat",
        "tcp",
        22,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ssh remote-admin on tcp/22 during egress"
    },
    {
        "tcp-ssh-source-service-exposed-service",
        "tcp",
        22,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: ssh remote-admin on tcp/22 during source-service"
    },
    {
        "tcp-ssh-source-service-management-plane",
        "tcp",
        22,
        "src",
        "management-plane",
        "high",
        "management interface traffic observed: ssh remote-admin on tcp/22 during source-service"
    },
    {
        "tcp-ssh-source-service-legacy-compat",
        "tcp",
        22,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ssh remote-admin on tcp/22 during source-service"
    },
    {
        "tcp-ssh-lateral-exposed-service",
        "tcp",
        22,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ssh remote-admin on tcp/22 during lateral"
    },
    {
        "tcp-ssh-lateral-management-plane",
        "tcp",
        22,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: ssh remote-admin on tcp/22 during lateral"
    },
    {
        "tcp-ssh-lateral-legacy-compat",
        "tcp",
        22,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ssh remote-admin on tcp/22 during lateral"
    },
    {
        "tcp-ssh-inventory-exposed-service",
        "tcp",
        22,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ssh remote-admin on tcp/22 during inventory"
    },
    {
        "tcp-ssh-inventory-management-plane",
        "tcp",
        22,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: ssh remote-admin on tcp/22 during inventory"
    },
    {
        "tcp-ssh-inventory-legacy-compat",
        "tcp",
        22,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ssh remote-admin on tcp/22 during inventory"
    },
    {
        "tcp-ssh-admin-plane-exposed-service",
        "tcp",
        22,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ssh remote-admin on tcp/22 during admin-plane"
    },
    {
        "tcp-ssh-admin-plane-management-plane",
        "tcp",
        22,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: ssh remote-admin on tcp/22 during admin-plane"
    },
    {
        "tcp-ssh-admin-plane-legacy-compat",
        "tcp",
        22,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ssh remote-admin on tcp/22 during admin-plane"
    },
    {
        "tcp-telnet-ingress-exposed-service",
        "tcp",
        23,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: telnet cleartext-admin on tcp/23 during ingress"
    },
    {
        "tcp-telnet-ingress-cleartext-risk",
        "tcp",
        23,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: telnet cleartext-admin on tcp/23 during ingress"
    },
    {
        "tcp-telnet-ingress-legacy-compat",
        "tcp",
        23,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: telnet cleartext-admin on tcp/23 during ingress"
    },
    {
        "tcp-telnet-egress-exposed-service",
        "tcp",
        23,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: telnet cleartext-admin on tcp/23 during egress"
    },
    {
        "tcp-telnet-egress-cleartext-risk",
        "tcp",
        23,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: telnet cleartext-admin on tcp/23 during egress"
    },
    {
        "tcp-telnet-egress-legacy-compat",
        "tcp",
        23,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: telnet cleartext-admin on tcp/23 during egress"
    },
    {
        "tcp-telnet-source-service-exposed-service",
        "tcp",
        23,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: telnet cleartext-admin on tcp/23 during source-service"
    },
    {
        "tcp-telnet-source-service-cleartext-risk",
        "tcp",
        23,
        "src",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: telnet cleartext-admin on tcp/23 during source-service"
    },
    {
        "tcp-telnet-source-service-legacy-compat",
        "tcp",
        23,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: telnet cleartext-admin on tcp/23 during source-service"
    },
    {
        "tcp-telnet-lateral-exposed-service",
        "tcp",
        23,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: telnet cleartext-admin on tcp/23 during lateral"
    },
    {
        "tcp-telnet-lateral-cleartext-risk",
        "tcp",
        23,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: telnet cleartext-admin on tcp/23 during lateral"
    },
    {
        "tcp-telnet-lateral-legacy-compat",
        "tcp",
        23,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: telnet cleartext-admin on tcp/23 during lateral"
    },
    {
        "tcp-telnet-inventory-exposed-service",
        "tcp",
        23,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: telnet cleartext-admin on tcp/23 during inventory"
    },
    {
        "tcp-telnet-inventory-cleartext-risk",
        "tcp",
        23,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: telnet cleartext-admin on tcp/23 during inventory"
    },
    {
        "tcp-telnet-inventory-legacy-compat",
        "tcp",
        23,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: telnet cleartext-admin on tcp/23 during inventory"
    },
    {
        "tcp-telnet-admin-plane-exposed-service",
        "tcp",
        23,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: telnet cleartext-admin on tcp/23 during admin-plane"
    },
    {
        "tcp-telnet-admin-plane-cleartext-risk",
        "tcp",
        23,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: telnet cleartext-admin on tcp/23 during admin-plane"
    },
    {
        "tcp-telnet-admin-plane-legacy-compat",
        "tcp",
        23,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: telnet cleartext-admin on tcp/23 during admin-plane"
    },
    {
        "tcp-smtp-ingress-exposed-service",
        "tcp",
        25,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: smtp mail-transfer on tcp/25 during ingress"
    },
    {
        "tcp-smtp-ingress-cleartext-risk",
        "tcp",
        25,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: smtp mail-transfer on tcp/25 during ingress"
    },
    {
        "tcp-smtp-ingress-legacy-compat",
        "tcp",
        25,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: smtp mail-transfer on tcp/25 during ingress"
    },
    {
        "tcp-smtp-egress-exposed-service",
        "tcp",
        25,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: smtp mail-transfer on tcp/25 during egress"
    },
    {
        "tcp-smtp-egress-cleartext-risk",
        "tcp",
        25,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: smtp mail-transfer on tcp/25 during egress"
    },
    {
        "tcp-smtp-egress-legacy-compat",
        "tcp",
        25,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: smtp mail-transfer on tcp/25 during egress"
    },
    {
        "tcp-smtp-source-service-exposed-service",
        "tcp",
        25,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: smtp mail-transfer on tcp/25 during source-service"
    },
    {
        "tcp-smtp-source-service-cleartext-risk",
        "tcp",
        25,
        "src",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: smtp mail-transfer on tcp/25 during source-service"
    },
    {
        "tcp-smtp-source-service-legacy-compat",
        "tcp",
        25,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: smtp mail-transfer on tcp/25 during source-service"
    },
    {
        "tcp-smtp-lateral-exposed-service",
        "tcp",
        25,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: smtp mail-transfer on tcp/25 during lateral"
    },
    {
        "tcp-smtp-lateral-cleartext-risk",
        "tcp",
        25,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: smtp mail-transfer on tcp/25 during lateral"
    },
    {
        "tcp-smtp-lateral-legacy-compat",
        "tcp",
        25,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: smtp mail-transfer on tcp/25 during lateral"
    },
    {
        "tcp-smtp-inventory-exposed-service",
        "tcp",
        25,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: smtp mail-transfer on tcp/25 during inventory"
    },
    {
        "tcp-smtp-inventory-cleartext-risk",
        "tcp",
        25,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: smtp mail-transfer on tcp/25 during inventory"
    },
    {
        "tcp-smtp-inventory-legacy-compat",
        "tcp",
        25,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: smtp mail-transfer on tcp/25 during inventory"
    },
    {
        "tcp-smtp-admin-plane-exposed-service",
        "tcp",
        25,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: smtp mail-transfer on tcp/25 during admin-plane"
    },
    {
        "tcp-smtp-admin-plane-cleartext-risk",
        "tcp",
        25,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: smtp mail-transfer on tcp/25 during admin-plane"
    },
    {
        "tcp-smtp-admin-plane-legacy-compat",
        "tcp",
        25,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: smtp mail-transfer on tcp/25 during admin-plane"
    },
    {
        "tcp-dns-ingress-exposed-service",
        "tcp",
        53,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: dns name-resolution on tcp/53 during ingress"
    },
    {
        "tcp-dns-ingress-legacy-compat",
        "tcp",
        53,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: dns name-resolution on tcp/53 during ingress"
    },
    {
        "tcp-dns-egress-exposed-service",
        "tcp",
        53,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: dns name-resolution on tcp/53 during egress"
    },
    {
        "tcp-dns-egress-legacy-compat",
        "tcp",
        53,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: dns name-resolution on tcp/53 during egress"
    },
    {
        "tcp-dns-source-service-exposed-service",
        "tcp",
        53,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: dns name-resolution on tcp/53 during source-service"
    },
    {
        "tcp-dns-source-service-legacy-compat",
        "tcp",
        53,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: dns name-resolution on tcp/53 during source-service"
    },
    {
        "tcp-dns-lateral-exposed-service",
        "tcp",
        53,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: dns name-resolution on tcp/53 during lateral"
    },
    {
        "tcp-dns-lateral-legacy-compat",
        "tcp",
        53,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: dns name-resolution on tcp/53 during lateral"
    },
    {
        "tcp-dns-inventory-exposed-service",
        "tcp",
        53,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: dns name-resolution on tcp/53 during inventory"
    },
    {
        "tcp-dns-inventory-legacy-compat",
        "tcp",
        53,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: dns name-resolution on tcp/53 during inventory"
    },
    {
        "tcp-dns-admin-plane-exposed-service",
        "tcp",
        53,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: dns name-resolution on tcp/53 during admin-plane"
    },
    {
        "tcp-dns-admin-plane-legacy-compat",
        "tcp",
        53,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: dns name-resolution on tcp/53 during admin-plane"
    },
    {
        "udp-dns-ingress-exposed-service",
        "udp",
        53,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: dns name-resolution on udp/53 during ingress"
    },
    {
        "udp-dns-ingress-legacy-compat",
        "udp",
        53,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: dns name-resolution on udp/53 during ingress"
    },
    {
        "udp-dns-egress-exposed-service",
        "udp",
        53,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: dns name-resolution on udp/53 during egress"
    },
    {
        "udp-dns-egress-legacy-compat",
        "udp",
        53,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: dns name-resolution on udp/53 during egress"
    },
    {
        "udp-dns-source-service-exposed-service",
        "udp",
        53,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: dns name-resolution on udp/53 during source-service"
    },
    {
        "udp-dns-source-service-legacy-compat",
        "udp",
        53,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: dns name-resolution on udp/53 during source-service"
    },
    {
        "udp-dns-lateral-exposed-service",
        "udp",
        53,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: dns name-resolution on udp/53 during lateral"
    },
    {
        "udp-dns-lateral-legacy-compat",
        "udp",
        53,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: dns name-resolution on udp/53 during lateral"
    },
    {
        "udp-dns-inventory-exposed-service",
        "udp",
        53,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: dns name-resolution on udp/53 during inventory"
    },
    {
        "udp-dns-inventory-legacy-compat",
        "udp",
        53,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: dns name-resolution on udp/53 during inventory"
    },
    {
        "udp-dns-admin-plane-exposed-service",
        "udp",
        53,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: dns name-resolution on udp/53 during admin-plane"
    },
    {
        "udp-dns-admin-plane-legacy-compat",
        "udp",
        53,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: dns name-resolution on udp/53 during admin-plane"
    },
    {
        "tcp-dhcp-ingress-exposed-service",
        "tcp",
        67,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: dhcp addressing on tcp/67 during ingress"
    },
    {
        "tcp-dhcp-ingress-legacy-compat",
        "tcp",
        67,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: dhcp addressing on tcp/67 during ingress"
    },
    {
        "tcp-dhcp-egress-exposed-service",
        "tcp",
        67,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: dhcp addressing on tcp/67 during egress"
    },
    {
        "tcp-dhcp-egress-legacy-compat",
        "tcp",
        67,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: dhcp addressing on tcp/67 during egress"
    },
    {
        "tcp-dhcp-source-service-exposed-service",
        "tcp",
        67,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: dhcp addressing on tcp/67 during source-service"
    },
    {
        "tcp-dhcp-source-service-legacy-compat",
        "tcp",
        67,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: dhcp addressing on tcp/67 during source-service"
    },
    {
        "tcp-dhcp-lateral-exposed-service",
        "tcp",
        67,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: dhcp addressing on tcp/67 during lateral"
    },
    {
        "tcp-dhcp-lateral-legacy-compat",
        "tcp",
        67,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: dhcp addressing on tcp/67 during lateral"
    },
    {
        "tcp-dhcp-inventory-exposed-service",
        "tcp",
        67,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: dhcp addressing on tcp/67 during inventory"
    },
    {
        "tcp-dhcp-inventory-legacy-compat",
        "tcp",
        67,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: dhcp addressing on tcp/67 during inventory"
    },
    {
        "tcp-dhcp-admin-plane-exposed-service",
        "tcp",
        67,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: dhcp addressing on tcp/67 during admin-plane"
    },
    {
        "tcp-dhcp-admin-plane-legacy-compat",
        "tcp",
        67,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: dhcp addressing on tcp/67 during admin-plane"
    },
    {
        "udp-dhcp-ingress-exposed-service",
        "udp",
        67,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: dhcp addressing on udp/67 during ingress"
    },
    {
        "udp-dhcp-ingress-legacy-compat",
        "udp",
        67,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: dhcp addressing on udp/67 during ingress"
    },
    {
        "udp-dhcp-egress-exposed-service",
        "udp",
        67,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: dhcp addressing on udp/67 during egress"
    },
    {
        "udp-dhcp-egress-legacy-compat",
        "udp",
        67,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: dhcp addressing on udp/67 during egress"
    },
    {
        "udp-dhcp-source-service-exposed-service",
        "udp",
        67,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: dhcp addressing on udp/67 during source-service"
    },
    {
        "udp-dhcp-source-service-legacy-compat",
        "udp",
        67,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: dhcp addressing on udp/67 during source-service"
    },
    {
        "udp-dhcp-lateral-exposed-service",
        "udp",
        67,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: dhcp addressing on udp/67 during lateral"
    },
    {
        "udp-dhcp-lateral-legacy-compat",
        "udp",
        67,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: dhcp addressing on udp/67 during lateral"
    },
    {
        "udp-dhcp-inventory-exposed-service",
        "udp",
        67,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: dhcp addressing on udp/67 during inventory"
    },
    {
        "udp-dhcp-inventory-legacy-compat",
        "udp",
        67,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: dhcp addressing on udp/67 during inventory"
    },
    {
        "udp-dhcp-admin-plane-exposed-service",
        "udp",
        67,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: dhcp addressing on udp/67 during admin-plane"
    },
    {
        "udp-dhcp-admin-plane-legacy-compat",
        "udp",
        67,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: dhcp addressing on udp/67 during admin-plane"
    },
    {
        "tcp-tftp-ingress-exposed-service",
        "tcp",
        69,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: tftp unauth-file-transfer on tcp/69 during ingress"
    },
    {
        "tcp-tftp-ingress-cleartext-risk",
        "tcp",
        69,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: tftp unauth-file-transfer on tcp/69 during ingress"
    },
    {
        "tcp-tftp-ingress-legacy-compat",
        "tcp",
        69,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: tftp unauth-file-transfer on tcp/69 during ingress"
    },
    {
        "tcp-tftp-egress-exposed-service",
        "tcp",
        69,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: tftp unauth-file-transfer on tcp/69 during egress"
    },
    {
        "tcp-tftp-egress-cleartext-risk",
        "tcp",
        69,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: tftp unauth-file-transfer on tcp/69 during egress"
    },
    {
        "tcp-tftp-egress-legacy-compat",
        "tcp",
        69,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: tftp unauth-file-transfer on tcp/69 during egress"
    },
    {
        "tcp-tftp-source-service-exposed-service",
        "tcp",
        69,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: tftp unauth-file-transfer on tcp/69 during source-service"
    },
    {
        "tcp-tftp-source-service-cleartext-risk",
        "tcp",
        69,
        "src",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: tftp unauth-file-transfer on tcp/69 during source-service"
    },
    {
        "tcp-tftp-source-service-legacy-compat",
        "tcp",
        69,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: tftp unauth-file-transfer on tcp/69 during source-service"
    },
    {
        "tcp-tftp-lateral-exposed-service",
        "tcp",
        69,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: tftp unauth-file-transfer on tcp/69 during lateral"
    },
    {
        "tcp-tftp-lateral-cleartext-risk",
        "tcp",
        69,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: tftp unauth-file-transfer on tcp/69 during lateral"
    },
    {
        "tcp-tftp-lateral-legacy-compat",
        "tcp",
        69,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: tftp unauth-file-transfer on tcp/69 during lateral"
    },
    {
        "tcp-tftp-inventory-exposed-service",
        "tcp",
        69,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: tftp unauth-file-transfer on tcp/69 during inventory"
    },
    {
        "tcp-tftp-inventory-cleartext-risk",
        "tcp",
        69,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: tftp unauth-file-transfer on tcp/69 during inventory"
    },
    {
        "tcp-tftp-inventory-legacy-compat",
        "tcp",
        69,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: tftp unauth-file-transfer on tcp/69 during inventory"
    },
    {
        "tcp-tftp-admin-plane-exposed-service",
        "tcp",
        69,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: tftp unauth-file-transfer on tcp/69 during admin-plane"
    },
    {
        "tcp-tftp-admin-plane-cleartext-risk",
        "tcp",
        69,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: tftp unauth-file-transfer on tcp/69 during admin-plane"
    },
    {
        "tcp-tftp-admin-plane-legacy-compat",
        "tcp",
        69,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: tftp unauth-file-transfer on tcp/69 during admin-plane"
    },
    {
        "udp-tftp-ingress-exposed-service",
        "udp",
        69,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: tftp unauth-file-transfer on udp/69 during ingress"
    },
    {
        "udp-tftp-ingress-cleartext-risk",
        "udp",
        69,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: tftp unauth-file-transfer on udp/69 during ingress"
    },
    {
        "udp-tftp-ingress-legacy-compat",
        "udp",
        69,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: tftp unauth-file-transfer on udp/69 during ingress"
    },
    {
        "udp-tftp-egress-exposed-service",
        "udp",
        69,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: tftp unauth-file-transfer on udp/69 during egress"
    },
    {
        "udp-tftp-egress-cleartext-risk",
        "udp",
        69,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: tftp unauth-file-transfer on udp/69 during egress"
    },
    {
        "udp-tftp-egress-legacy-compat",
        "udp",
        69,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: tftp unauth-file-transfer on udp/69 during egress"
    },
    {
        "udp-tftp-source-service-exposed-service",
        "udp",
        69,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: tftp unauth-file-transfer on udp/69 during source-service"
    },
    {
        "udp-tftp-source-service-cleartext-risk",
        "udp",
        69,
        "src",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: tftp unauth-file-transfer on udp/69 during source-service"
    },
    {
        "udp-tftp-source-service-legacy-compat",
        "udp",
        69,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: tftp unauth-file-transfer on udp/69 during source-service"
    },
    {
        "udp-tftp-lateral-exposed-service",
        "udp",
        69,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: tftp unauth-file-transfer on udp/69 during lateral"
    },
    {
        "udp-tftp-lateral-cleartext-risk",
        "udp",
        69,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: tftp unauth-file-transfer on udp/69 during lateral"
    },
    {
        "udp-tftp-lateral-legacy-compat",
        "udp",
        69,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: tftp unauth-file-transfer on udp/69 during lateral"
    },
    {
        "udp-tftp-inventory-exposed-service",
        "udp",
        69,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: tftp unauth-file-transfer on udp/69 during inventory"
    },
    {
        "udp-tftp-inventory-cleartext-risk",
        "udp",
        69,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: tftp unauth-file-transfer on udp/69 during inventory"
    },
    {
        "udp-tftp-inventory-legacy-compat",
        "udp",
        69,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: tftp unauth-file-transfer on udp/69 during inventory"
    },
    {
        "udp-tftp-admin-plane-exposed-service",
        "udp",
        69,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: tftp unauth-file-transfer on udp/69 during admin-plane"
    },
    {
        "udp-tftp-admin-plane-cleartext-risk",
        "udp",
        69,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: tftp unauth-file-transfer on udp/69 during admin-plane"
    },
    {
        "udp-tftp-admin-plane-legacy-compat",
        "udp",
        69,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: tftp unauth-file-transfer on udp/69 during admin-plane"
    },
    {
        "tcp-http-ingress-exposed-service",
        "tcp",
        80,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: http web on tcp/80 during ingress"
    },
    {
        "tcp-http-ingress-cleartext-risk",
        "tcp",
        80,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: http web on tcp/80 during ingress"
    },
    {
        "tcp-http-ingress-legacy-compat",
        "tcp",
        80,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: http web on tcp/80 during ingress"
    },
    {
        "tcp-http-egress-exposed-service",
        "tcp",
        80,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: http web on tcp/80 during egress"
    },
    {
        "tcp-http-egress-cleartext-risk",
        "tcp",
        80,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: http web on tcp/80 during egress"
    },
    {
        "tcp-http-egress-legacy-compat",
        "tcp",
        80,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: http web on tcp/80 during egress"
    },
    {
        "tcp-http-source-service-exposed-service",
        "tcp",
        80,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: http web on tcp/80 during source-service"
    },
    {
        "tcp-http-source-service-cleartext-risk",
        "tcp",
        80,
        "src",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: http web on tcp/80 during source-service"
    },
    {
        "tcp-http-source-service-legacy-compat",
        "tcp",
        80,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: http web on tcp/80 during source-service"
    },
    {
        "tcp-http-lateral-exposed-service",
        "tcp",
        80,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: http web on tcp/80 during lateral"
    },
    {
        "tcp-http-lateral-cleartext-risk",
        "tcp",
        80,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: http web on tcp/80 during lateral"
    },
    {
        "tcp-http-lateral-legacy-compat",
        "tcp",
        80,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: http web on tcp/80 during lateral"
    },
    {
        "tcp-http-inventory-exposed-service",
        "tcp",
        80,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: http web on tcp/80 during inventory"
    },
    {
        "tcp-http-inventory-cleartext-risk",
        "tcp",
        80,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: http web on tcp/80 during inventory"
    },
    {
        "tcp-http-inventory-legacy-compat",
        "tcp",
        80,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: http web on tcp/80 during inventory"
    },
    {
        "tcp-http-admin-plane-exposed-service",
        "tcp",
        80,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: http web on tcp/80 during admin-plane"
    },
    {
        "tcp-http-admin-plane-cleartext-risk",
        "tcp",
        80,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: http web on tcp/80 during admin-plane"
    },
    {
        "tcp-http-admin-plane-legacy-compat",
        "tcp",
        80,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: http web on tcp/80 during admin-plane"
    },
    {
        "tcp-kerberos-ingress-exposed-service",
        "tcp",
        88,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: kerberos identity on tcp/88 during ingress"
    },
    {
        "tcp-kerberos-ingress-identity-plane",
        "tcp",
        88,
        "dst",
        "identity-plane",
        "medium",
        "identity infrastructure traffic observed: kerberos identity on tcp/88 during ingress"
    },
    {
        "tcp-kerberos-ingress-legacy-compat",
        "tcp",
        88,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: kerberos identity on tcp/88 during ingress"
    },
    {
        "tcp-kerberos-egress-exposed-service",
        "tcp",
        88,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: kerberos identity on tcp/88 during egress"
    },
    {
        "tcp-kerberos-egress-identity-plane",
        "tcp",
        88,
        "dst",
        "identity-plane",
        "medium",
        "identity infrastructure traffic observed: kerberos identity on tcp/88 during egress"
    },
    {
        "tcp-kerberos-egress-legacy-compat",
        "tcp",
        88,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: kerberos identity on tcp/88 during egress"
    },
    {
        "tcp-kerberos-source-service-exposed-service",
        "tcp",
        88,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: kerberos identity on tcp/88 during source-service"
    },
    {
        "tcp-kerberos-source-service-identity-plane",
        "tcp",
        88,
        "src",
        "identity-plane",
        "medium",
        "identity infrastructure traffic observed: kerberos identity on tcp/88 during source-service"
    },
    {
        "tcp-kerberos-source-service-legacy-compat",
        "tcp",
        88,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: kerberos identity on tcp/88 during source-service"
    },
    {
        "tcp-kerberos-lateral-exposed-service",
        "tcp",
        88,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: kerberos identity on tcp/88 during lateral"
    },
    {
        "tcp-kerberos-lateral-identity-plane",
        "tcp",
        88,
        "dst",
        "identity-plane",
        "medium",
        "identity infrastructure traffic observed: kerberos identity on tcp/88 during lateral"
    },
    {
        "tcp-kerberos-lateral-legacy-compat",
        "tcp",
        88,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: kerberos identity on tcp/88 during lateral"
    },
    {
        "tcp-kerberos-inventory-exposed-service",
        "tcp",
        88,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: kerberos identity on tcp/88 during inventory"
    },
    {
        "tcp-kerberos-inventory-identity-plane",
        "tcp",
        88,
        "dst",
        "identity-plane",
        "medium",
        "identity infrastructure traffic observed: kerberos identity on tcp/88 during inventory"
    },
    {
        "tcp-kerberos-inventory-legacy-compat",
        "tcp",
        88,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: kerberos identity on tcp/88 during inventory"
    },
    {
        "tcp-kerberos-admin-plane-exposed-service",
        "tcp",
        88,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: kerberos identity on tcp/88 during admin-plane"
    },
    {
        "tcp-kerberos-admin-plane-identity-plane",
        "tcp",
        88,
        "dst",
        "identity-plane",
        "medium",
        "identity infrastructure traffic observed: kerberos identity on tcp/88 during admin-plane"
    },
    {
        "tcp-kerberos-admin-plane-legacy-compat",
        "tcp",
        88,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: kerberos identity on tcp/88 during admin-plane"
    },
    {
        "tcp-pop3-ingress-exposed-service",
        "tcp",
        110,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: pop3 mail-retrieval on tcp/110 during ingress"
    },
    {
        "tcp-pop3-ingress-cleartext-risk",
        "tcp",
        110,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: pop3 mail-retrieval on tcp/110 during ingress"
    },
    {
        "tcp-pop3-ingress-legacy-compat",
        "tcp",
        110,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: pop3 mail-retrieval on tcp/110 during ingress"
    },
    {
        "tcp-pop3-egress-exposed-service",
        "tcp",
        110,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: pop3 mail-retrieval on tcp/110 during egress"
    },
    {
        "tcp-pop3-egress-cleartext-risk",
        "tcp",
        110,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: pop3 mail-retrieval on tcp/110 during egress"
    },
    {
        "tcp-pop3-egress-legacy-compat",
        "tcp",
        110,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: pop3 mail-retrieval on tcp/110 during egress"
    },
    {
        "tcp-pop3-source-service-exposed-service",
        "tcp",
        110,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: pop3 mail-retrieval on tcp/110 during source-service"
    },
    {
        "tcp-pop3-source-service-cleartext-risk",
        "tcp",
        110,
        "src",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: pop3 mail-retrieval on tcp/110 during source-service"
    },
    {
        "tcp-pop3-source-service-legacy-compat",
        "tcp",
        110,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: pop3 mail-retrieval on tcp/110 during source-service"
    },
    {
        "tcp-pop3-lateral-exposed-service",
        "tcp",
        110,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: pop3 mail-retrieval on tcp/110 during lateral"
    },
    {
        "tcp-pop3-lateral-cleartext-risk",
        "tcp",
        110,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: pop3 mail-retrieval on tcp/110 during lateral"
    },
    {
        "tcp-pop3-lateral-legacy-compat",
        "tcp",
        110,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: pop3 mail-retrieval on tcp/110 during lateral"
    },
    {
        "tcp-pop3-inventory-exposed-service",
        "tcp",
        110,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: pop3 mail-retrieval on tcp/110 during inventory"
    },
    {
        "tcp-pop3-inventory-cleartext-risk",
        "tcp",
        110,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: pop3 mail-retrieval on tcp/110 during inventory"
    },
    {
        "tcp-pop3-inventory-legacy-compat",
        "tcp",
        110,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: pop3 mail-retrieval on tcp/110 during inventory"
    },
    {
        "tcp-pop3-admin-plane-exposed-service",
        "tcp",
        110,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: pop3 mail-retrieval on tcp/110 during admin-plane"
    },
    {
        "tcp-pop3-admin-plane-cleartext-risk",
        "tcp",
        110,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: pop3 mail-retrieval on tcp/110 during admin-plane"
    },
    {
        "tcp-pop3-admin-plane-legacy-compat",
        "tcp",
        110,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: pop3 mail-retrieval on tcp/110 during admin-plane"
    },
    {
        "tcp-msrpc-ingress-exposed-service",
        "tcp",
        135,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: msrpc windows-rpc on tcp/135 during ingress"
    },
    {
        "tcp-msrpc-ingress-management-plane",
        "tcp",
        135,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: msrpc windows-rpc on tcp/135 during ingress"
    },
    {
        "tcp-msrpc-ingress-legacy-compat",
        "tcp",
        135,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: msrpc windows-rpc on tcp/135 during ingress"
    },
    {
        "tcp-msrpc-egress-exposed-service",
        "tcp",
        135,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: msrpc windows-rpc on tcp/135 during egress"
    },
    {
        "tcp-msrpc-egress-management-plane",
        "tcp",
        135,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: msrpc windows-rpc on tcp/135 during egress"
    },
    {
        "tcp-msrpc-egress-legacy-compat",
        "tcp",
        135,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: msrpc windows-rpc on tcp/135 during egress"
    },
    {
        "tcp-msrpc-source-service-exposed-service",
        "tcp",
        135,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: msrpc windows-rpc on tcp/135 during source-service"
    },
    {
        "tcp-msrpc-source-service-management-plane",
        "tcp",
        135,
        "src",
        "management-plane",
        "high",
        "management interface traffic observed: msrpc windows-rpc on tcp/135 during source-service"
    },
    {
        "tcp-msrpc-source-service-legacy-compat",
        "tcp",
        135,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: msrpc windows-rpc on tcp/135 during source-service"
    },
    {
        "tcp-msrpc-lateral-exposed-service",
        "tcp",
        135,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: msrpc windows-rpc on tcp/135 during lateral"
    },
    {
        "tcp-msrpc-lateral-management-plane",
        "tcp",
        135,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: msrpc windows-rpc on tcp/135 during lateral"
    },
    {
        "tcp-msrpc-lateral-legacy-compat",
        "tcp",
        135,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: msrpc windows-rpc on tcp/135 during lateral"
    },
    {
        "tcp-msrpc-inventory-exposed-service",
        "tcp",
        135,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: msrpc windows-rpc on tcp/135 during inventory"
    },
    {
        "tcp-msrpc-inventory-management-plane",
        "tcp",
        135,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: msrpc windows-rpc on tcp/135 during inventory"
    },
    {
        "tcp-msrpc-inventory-legacy-compat",
        "tcp",
        135,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: msrpc windows-rpc on tcp/135 during inventory"
    },
    {
        "tcp-msrpc-admin-plane-exposed-service",
        "tcp",
        135,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: msrpc windows-rpc on tcp/135 during admin-plane"
    },
    {
        "tcp-msrpc-admin-plane-management-plane",
        "tcp",
        135,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: msrpc windows-rpc on tcp/135 during admin-plane"
    },
    {
        "tcp-msrpc-admin-plane-legacy-compat",
        "tcp",
        135,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: msrpc windows-rpc on tcp/135 during admin-plane"
    },
    {
        "tcp-netbios-ingress-exposed-service",
        "tcp",
        139,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: netbios windows-file-sharing on tcp/139 during ingress"
    },
    {
        "tcp-netbios-ingress-legacy-compat",
        "tcp",
        139,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: netbios windows-file-sharing on tcp/139 during ingress"
    },
    {
        "tcp-netbios-egress-exposed-service",
        "tcp",
        139,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: netbios windows-file-sharing on tcp/139 during egress"
    },
    {
        "tcp-netbios-egress-legacy-compat",
        "tcp",
        139,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: netbios windows-file-sharing on tcp/139 during egress"
    },
    {
        "tcp-netbios-source-service-exposed-service",
        "tcp",
        139,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: netbios windows-file-sharing on tcp/139 during source-service"
    },
    {
        "tcp-netbios-source-service-legacy-compat",
        "tcp",
        139,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: netbios windows-file-sharing on tcp/139 during source-service"
    },
    {
        "tcp-netbios-lateral-exposed-service",
        "tcp",
        139,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: netbios windows-file-sharing on tcp/139 during lateral"
    },
    {
        "tcp-netbios-lateral-legacy-compat",
        "tcp",
        139,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: netbios windows-file-sharing on tcp/139 during lateral"
    },
    {
        "tcp-netbios-inventory-exposed-service",
        "tcp",
        139,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: netbios windows-file-sharing on tcp/139 during inventory"
    },
    {
        "tcp-netbios-inventory-legacy-compat",
        "tcp",
        139,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: netbios windows-file-sharing on tcp/139 during inventory"
    },
    {
        "tcp-netbios-admin-plane-exposed-service",
        "tcp",
        139,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: netbios windows-file-sharing on tcp/139 during admin-plane"
    },
    {
        "tcp-netbios-admin-plane-legacy-compat",
        "tcp",
        139,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: netbios windows-file-sharing on tcp/139 during admin-plane"
    },
    {
        "tcp-imap-ingress-exposed-service",
        "tcp",
        143,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: imap mail-retrieval on tcp/143 during ingress"
    },
    {
        "tcp-imap-ingress-cleartext-risk",
        "tcp",
        143,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: imap mail-retrieval on tcp/143 during ingress"
    },
    {
        "tcp-imap-ingress-legacy-compat",
        "tcp",
        143,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: imap mail-retrieval on tcp/143 during ingress"
    },
    {
        "tcp-imap-egress-exposed-service",
        "tcp",
        143,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: imap mail-retrieval on tcp/143 during egress"
    },
    {
        "tcp-imap-egress-cleartext-risk",
        "tcp",
        143,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: imap mail-retrieval on tcp/143 during egress"
    },
    {
        "tcp-imap-egress-legacy-compat",
        "tcp",
        143,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: imap mail-retrieval on tcp/143 during egress"
    },
    {
        "tcp-imap-source-service-exposed-service",
        "tcp",
        143,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: imap mail-retrieval on tcp/143 during source-service"
    },
    {
        "tcp-imap-source-service-cleartext-risk",
        "tcp",
        143,
        "src",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: imap mail-retrieval on tcp/143 during source-service"
    },
    {
        "tcp-imap-source-service-legacy-compat",
        "tcp",
        143,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: imap mail-retrieval on tcp/143 during source-service"
    },
    {
        "tcp-imap-lateral-exposed-service",
        "tcp",
        143,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: imap mail-retrieval on tcp/143 during lateral"
    },
    {
        "tcp-imap-lateral-cleartext-risk",
        "tcp",
        143,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: imap mail-retrieval on tcp/143 during lateral"
    },
    {
        "tcp-imap-lateral-legacy-compat",
        "tcp",
        143,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: imap mail-retrieval on tcp/143 during lateral"
    },
    {
        "tcp-imap-inventory-exposed-service",
        "tcp",
        143,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: imap mail-retrieval on tcp/143 during inventory"
    },
    {
        "tcp-imap-inventory-cleartext-risk",
        "tcp",
        143,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: imap mail-retrieval on tcp/143 during inventory"
    },
    {
        "tcp-imap-inventory-legacy-compat",
        "tcp",
        143,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: imap mail-retrieval on tcp/143 during inventory"
    },
    {
        "tcp-imap-admin-plane-exposed-service",
        "tcp",
        143,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: imap mail-retrieval on tcp/143 during admin-plane"
    },
    {
        "tcp-imap-admin-plane-cleartext-risk",
        "tcp",
        143,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: imap mail-retrieval on tcp/143 during admin-plane"
    },
    {
        "tcp-imap-admin-plane-legacy-compat",
        "tcp",
        143,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: imap mail-retrieval on tcp/143 during admin-plane"
    },
    {
        "tcp-snmp-ingress-exposed-service",
        "tcp",
        161,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: snmp management on tcp/161 during ingress"
    },
    {
        "tcp-snmp-ingress-management-plane",
        "tcp",
        161,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: snmp management on tcp/161 during ingress"
    },
    {
        "tcp-snmp-ingress-legacy-compat",
        "tcp",
        161,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: snmp management on tcp/161 during ingress"
    },
    {
        "tcp-snmp-ingress-monitoring",
        "tcp",
        161,
        "dst",
        "monitoring",
        "low",
        "monitoring or telemetry service observed: snmp management on tcp/161 during ingress"
    },
    {
        "tcp-snmp-egress-exposed-service",
        "tcp",
        161,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: snmp management on tcp/161 during egress"
    },
    {
        "tcp-snmp-egress-management-plane",
        "tcp",
        161,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: snmp management on tcp/161 during egress"
    },
    {
        "tcp-snmp-egress-legacy-compat",
        "tcp",
        161,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: snmp management on tcp/161 during egress"
    },
    {
        "tcp-snmp-egress-monitoring",
        "tcp",
        161,
        "dst",
        "monitoring",
        "low",
        "monitoring or telemetry service observed: snmp management on tcp/161 during egress"
    },
    {
        "tcp-snmp-source-service-exposed-service",
        "tcp",
        161,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: snmp management on tcp/161 during source-service"
    },
    {
        "tcp-snmp-source-service-management-plane",
        "tcp",
        161,
        "src",
        "management-plane",
        "high",
        "management interface traffic observed: snmp management on tcp/161 during source-service"
    },
    {
        "tcp-snmp-source-service-legacy-compat",
        "tcp",
        161,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: snmp management on tcp/161 during source-service"
    },
    {
        "tcp-snmp-source-service-monitoring",
        "tcp",
        161,
        "src",
        "monitoring",
        "low",
        "monitoring or telemetry service observed: snmp management on tcp/161 during source-service"
    },
    {
        "tcp-snmp-lateral-exposed-service",
        "tcp",
        161,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: snmp management on tcp/161 during lateral"
    },
    {
        "tcp-snmp-lateral-management-plane",
        "tcp",
        161,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: snmp management on tcp/161 during lateral"
    },
    {
        "tcp-snmp-lateral-legacy-compat",
        "tcp",
        161,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: snmp management on tcp/161 during lateral"
    },
    {
        "tcp-snmp-lateral-monitoring",
        "tcp",
        161,
        "dst",
        "monitoring",
        "low",
        "monitoring or telemetry service observed: snmp management on tcp/161 during lateral"
    },
    {
        "tcp-snmp-inventory-exposed-service",
        "tcp",
        161,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: snmp management on tcp/161 during inventory"
    },
    {
        "tcp-snmp-inventory-management-plane",
        "tcp",
        161,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: snmp management on tcp/161 during inventory"
    },
    {
        "tcp-snmp-inventory-legacy-compat",
        "tcp",
        161,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: snmp management on tcp/161 during inventory"
    },
    {
        "tcp-snmp-inventory-monitoring",
        "tcp",
        161,
        "dst",
        "monitoring",
        "low",
        "monitoring or telemetry service observed: snmp management on tcp/161 during inventory"
    },
    {
        "tcp-snmp-admin-plane-exposed-service",
        "tcp",
        161,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: snmp management on tcp/161 during admin-plane"
    },
    {
        "tcp-snmp-admin-plane-management-plane",
        "tcp",
        161,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: snmp management on tcp/161 during admin-plane"
    },
    {
        "tcp-snmp-admin-plane-legacy-compat",
        "tcp",
        161,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: snmp management on tcp/161 during admin-plane"
    },
    {
        "tcp-snmp-admin-plane-monitoring",
        "tcp",
        161,
        "dst",
        "monitoring",
        "low",
        "monitoring or telemetry service observed: snmp management on tcp/161 during admin-plane"
    },
    {
        "udp-snmp-ingress-exposed-service",
        "udp",
        161,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: snmp management on udp/161 during ingress"
    },
    {
        "udp-snmp-ingress-management-plane",
        "udp",
        161,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: snmp management on udp/161 during ingress"
    },
    {
        "udp-snmp-ingress-legacy-compat",
        "udp",
        161,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: snmp management on udp/161 during ingress"
    },
    {
        "udp-snmp-ingress-monitoring",
        "udp",
        161,
        "dst",
        "monitoring",
        "low",
        "monitoring or telemetry service observed: snmp management on udp/161 during ingress"
    },
    {
        "udp-snmp-egress-exposed-service",
        "udp",
        161,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: snmp management on udp/161 during egress"
    },
    {
        "udp-snmp-egress-management-plane",
        "udp",
        161,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: snmp management on udp/161 during egress"
    },
    {
        "udp-snmp-egress-legacy-compat",
        "udp",
        161,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: snmp management on udp/161 during egress"
    },
    {
        "udp-snmp-egress-monitoring",
        "udp",
        161,
        "dst",
        "monitoring",
        "low",
        "monitoring or telemetry service observed: snmp management on udp/161 during egress"
    },
    {
        "udp-snmp-source-service-exposed-service",
        "udp",
        161,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: snmp management on udp/161 during source-service"
    },
    {
        "udp-snmp-source-service-management-plane",
        "udp",
        161,
        "src",
        "management-plane",
        "high",
        "management interface traffic observed: snmp management on udp/161 during source-service"
    },
    {
        "udp-snmp-source-service-legacy-compat",
        "udp",
        161,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: snmp management on udp/161 during source-service"
    },
    {
        "udp-snmp-source-service-monitoring",
        "udp",
        161,
        "src",
        "monitoring",
        "low",
        "monitoring or telemetry service observed: snmp management on udp/161 during source-service"
    },
    {
        "udp-snmp-lateral-exposed-service",
        "udp",
        161,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: snmp management on udp/161 during lateral"
    },
    {
        "udp-snmp-lateral-management-plane",
        "udp",
        161,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: snmp management on udp/161 during lateral"
    },
    {
        "udp-snmp-lateral-legacy-compat",
        "udp",
        161,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: snmp management on udp/161 during lateral"
    },
    {
        "udp-snmp-lateral-monitoring",
        "udp",
        161,
        "dst",
        "monitoring",
        "low",
        "monitoring or telemetry service observed: snmp management on udp/161 during lateral"
    },
    {
        "udp-snmp-inventory-exposed-service",
        "udp",
        161,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: snmp management on udp/161 during inventory"
    },
    {
        "udp-snmp-inventory-management-plane",
        "udp",
        161,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: snmp management on udp/161 during inventory"
    },
    {
        "udp-snmp-inventory-legacy-compat",
        "udp",
        161,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: snmp management on udp/161 during inventory"
    },
    {
        "udp-snmp-inventory-monitoring",
        "udp",
        161,
        "dst",
        "monitoring",
        "low",
        "monitoring or telemetry service observed: snmp management on udp/161 during inventory"
    },
    {
        "udp-snmp-admin-plane-exposed-service",
        "udp",
        161,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: snmp management on udp/161 during admin-plane"
    },
    {
        "udp-snmp-admin-plane-management-plane",
        "udp",
        161,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: snmp management on udp/161 during admin-plane"
    },
    {
        "udp-snmp-admin-plane-legacy-compat",
        "udp",
        161,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: snmp management on udp/161 during admin-plane"
    },
    {
        "udp-snmp-admin-plane-monitoring",
        "udp",
        161,
        "dst",
        "monitoring",
        "low",
        "monitoring or telemetry service observed: snmp management on udp/161 during admin-plane"
    },
    {
        "tcp-ldap-ingress-exposed-service",
        "tcp",
        389,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ldap directory on tcp/389 during ingress"
    },
    {
        "tcp-ldap-ingress-identity-plane",
        "tcp",
        389,
        "dst",
        "identity-plane",
        "medium",
        "identity infrastructure traffic observed: ldap directory on tcp/389 during ingress"
    },
    {
        "tcp-ldap-ingress-legacy-compat",
        "tcp",
        389,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ldap directory on tcp/389 during ingress"
    },
    {
        "tcp-ldap-egress-exposed-service",
        "tcp",
        389,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ldap directory on tcp/389 during egress"
    },
    {
        "tcp-ldap-egress-identity-plane",
        "tcp",
        389,
        "dst",
        "identity-plane",
        "medium",
        "identity infrastructure traffic observed: ldap directory on tcp/389 during egress"
    },
    {
        "tcp-ldap-egress-legacy-compat",
        "tcp",
        389,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ldap directory on tcp/389 during egress"
    },
    {
        "tcp-ldap-source-service-exposed-service",
        "tcp",
        389,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: ldap directory on tcp/389 during source-service"
    },
    {
        "tcp-ldap-source-service-identity-plane",
        "tcp",
        389,
        "src",
        "identity-plane",
        "medium",
        "identity infrastructure traffic observed: ldap directory on tcp/389 during source-service"
    },
    {
        "tcp-ldap-source-service-legacy-compat",
        "tcp",
        389,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ldap directory on tcp/389 during source-service"
    },
    {
        "tcp-ldap-lateral-exposed-service",
        "tcp",
        389,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ldap directory on tcp/389 during lateral"
    },
    {
        "tcp-ldap-lateral-identity-plane",
        "tcp",
        389,
        "dst",
        "identity-plane",
        "medium",
        "identity infrastructure traffic observed: ldap directory on tcp/389 during lateral"
    },
    {
        "tcp-ldap-lateral-legacy-compat",
        "tcp",
        389,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ldap directory on tcp/389 during lateral"
    },
    {
        "tcp-ldap-inventory-exposed-service",
        "tcp",
        389,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ldap directory on tcp/389 during inventory"
    },
    {
        "tcp-ldap-inventory-identity-plane",
        "tcp",
        389,
        "dst",
        "identity-plane",
        "medium",
        "identity infrastructure traffic observed: ldap directory on tcp/389 during inventory"
    },
    {
        "tcp-ldap-inventory-legacy-compat",
        "tcp",
        389,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ldap directory on tcp/389 during inventory"
    },
    {
        "tcp-ldap-admin-plane-exposed-service",
        "tcp",
        389,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ldap directory on tcp/389 during admin-plane"
    },
    {
        "tcp-ldap-admin-plane-identity-plane",
        "tcp",
        389,
        "dst",
        "identity-plane",
        "medium",
        "identity infrastructure traffic observed: ldap directory on tcp/389 during admin-plane"
    },
    {
        "tcp-ldap-admin-plane-legacy-compat",
        "tcp",
        389,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ldap directory on tcp/389 during admin-plane"
    },
    {
        "tcp-https-ingress-exposed-service",
        "tcp",
        443,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: https web-tls on tcp/443 during ingress"
    },
    {
        "tcp-https-ingress-legacy-compat",
        "tcp",
        443,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: https web-tls on tcp/443 during ingress"
    },
    {
        "tcp-https-egress-exposed-service",
        "tcp",
        443,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: https web-tls on tcp/443 during egress"
    },
    {
        "tcp-https-egress-legacy-compat",
        "tcp",
        443,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: https web-tls on tcp/443 during egress"
    },
    {
        "tcp-https-source-service-exposed-service",
        "tcp",
        443,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: https web-tls on tcp/443 during source-service"
    },
    {
        "tcp-https-source-service-legacy-compat",
        "tcp",
        443,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: https web-tls on tcp/443 during source-service"
    },
    {
        "tcp-https-lateral-exposed-service",
        "tcp",
        443,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: https web-tls on tcp/443 during lateral"
    },
    {
        "tcp-https-lateral-legacy-compat",
        "tcp",
        443,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: https web-tls on tcp/443 during lateral"
    },
    {
        "tcp-https-inventory-exposed-service",
        "tcp",
        443,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: https web-tls on tcp/443 during inventory"
    },
    {
        "tcp-https-inventory-legacy-compat",
        "tcp",
        443,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: https web-tls on tcp/443 during inventory"
    },
    {
        "tcp-https-admin-plane-exposed-service",
        "tcp",
        443,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: https web-tls on tcp/443 during admin-plane"
    },
    {
        "tcp-https-admin-plane-legacy-compat",
        "tcp",
        443,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: https web-tls on tcp/443 during admin-plane"
    },
    {
        "tcp-smb-ingress-exposed-service",
        "tcp",
        445,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: smb windows-file-sharing on tcp/445 during ingress"
    },
    {
        "tcp-smb-ingress-legacy-compat",
        "tcp",
        445,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: smb windows-file-sharing on tcp/445 during ingress"
    },
    {
        "tcp-smb-egress-exposed-service",
        "tcp",
        445,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: smb windows-file-sharing on tcp/445 during egress"
    },
    {
        "tcp-smb-egress-legacy-compat",
        "tcp",
        445,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: smb windows-file-sharing on tcp/445 during egress"
    },
    {
        "tcp-smb-source-service-exposed-service",
        "tcp",
        445,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: smb windows-file-sharing on tcp/445 during source-service"
    },
    {
        "tcp-smb-source-service-legacy-compat",
        "tcp",
        445,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: smb windows-file-sharing on tcp/445 during source-service"
    },
    {
        "tcp-smb-lateral-exposed-service",
        "tcp",
        445,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: smb windows-file-sharing on tcp/445 during lateral"
    },
    {
        "tcp-smb-lateral-legacy-compat",
        "tcp",
        445,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: smb windows-file-sharing on tcp/445 during lateral"
    },
    {
        "tcp-smb-inventory-exposed-service",
        "tcp",
        445,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: smb windows-file-sharing on tcp/445 during inventory"
    },
    {
        "tcp-smb-inventory-legacy-compat",
        "tcp",
        445,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: smb windows-file-sharing on tcp/445 during inventory"
    },
    {
        "tcp-smb-admin-plane-exposed-service",
        "tcp",
        445,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: smb windows-file-sharing on tcp/445 during admin-plane"
    },
    {
        "tcp-smb-admin-plane-legacy-compat",
        "tcp",
        445,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: smb windows-file-sharing on tcp/445 during admin-plane"
    },
    {
        "tcp-smtps-ingress-exposed-service",
        "tcp",
        465,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: smtps mail-tls on tcp/465 during ingress"
    },
    {
        "tcp-smtps-ingress-legacy-compat",
        "tcp",
        465,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: smtps mail-tls on tcp/465 during ingress"
    },
    {
        "tcp-smtps-egress-exposed-service",
        "tcp",
        465,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: smtps mail-tls on tcp/465 during egress"
    },
    {
        "tcp-smtps-egress-legacy-compat",
        "tcp",
        465,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: smtps mail-tls on tcp/465 during egress"
    },
    {
        "tcp-smtps-source-service-exposed-service",
        "tcp",
        465,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: smtps mail-tls on tcp/465 during source-service"
    },
    {
        "tcp-smtps-source-service-legacy-compat",
        "tcp",
        465,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: smtps mail-tls on tcp/465 during source-service"
    },
    {
        "tcp-smtps-lateral-exposed-service",
        "tcp",
        465,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: smtps mail-tls on tcp/465 during lateral"
    },
    {
        "tcp-smtps-lateral-legacy-compat",
        "tcp",
        465,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: smtps mail-tls on tcp/465 during lateral"
    },
    {
        "tcp-smtps-inventory-exposed-service",
        "tcp",
        465,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: smtps mail-tls on tcp/465 during inventory"
    },
    {
        "tcp-smtps-inventory-legacy-compat",
        "tcp",
        465,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: smtps mail-tls on tcp/465 during inventory"
    },
    {
        "tcp-smtps-admin-plane-exposed-service",
        "tcp",
        465,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: smtps mail-tls on tcp/465 during admin-plane"
    },
    {
        "tcp-smtps-admin-plane-legacy-compat",
        "tcp",
        465,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: smtps mail-tls on tcp/465 during admin-plane"
    },
    {
        "tcp-ike-ingress-exposed-service",
        "tcp",
        500,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ike vpn on tcp/500 during ingress"
    },
    {
        "tcp-ike-ingress-tunnel-or-vpn",
        "tcp",
        500,
        "dst",
        "tunnel-or-vpn",
        "medium",
        "tunneling or VPN service traffic observed: ike vpn on tcp/500 during ingress"
    },
    {
        "tcp-ike-ingress-legacy-compat",
        "tcp",
        500,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ike vpn on tcp/500 during ingress"
    },
    {
        "tcp-ike-egress-exposed-service",
        "tcp",
        500,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ike vpn on tcp/500 during egress"
    },
    {
        "tcp-ike-egress-tunnel-or-vpn",
        "tcp",
        500,
        "dst",
        "tunnel-or-vpn",
        "medium",
        "tunneling or VPN service traffic observed: ike vpn on tcp/500 during egress"
    },
    {
        "tcp-ike-egress-legacy-compat",
        "tcp",
        500,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ike vpn on tcp/500 during egress"
    },
    {
        "tcp-ike-source-service-exposed-service",
        "tcp",
        500,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: ike vpn on tcp/500 during source-service"
    },
    {
        "tcp-ike-source-service-tunnel-or-vpn",
        "tcp",
        500,
        "src",
        "tunnel-or-vpn",
        "medium",
        "tunneling or VPN service traffic observed: ike vpn on tcp/500 during source-service"
    },
    {
        "tcp-ike-source-service-legacy-compat",
        "tcp",
        500,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ike vpn on tcp/500 during source-service"
    },
    {
        "tcp-ike-lateral-exposed-service",
        "tcp",
        500,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ike vpn on tcp/500 during lateral"
    },
    {
        "tcp-ike-lateral-tunnel-or-vpn",
        "tcp",
        500,
        "dst",
        "tunnel-or-vpn",
        "medium",
        "tunneling or VPN service traffic observed: ike vpn on tcp/500 during lateral"
    },
    {
        "tcp-ike-lateral-legacy-compat",
        "tcp",
        500,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ike vpn on tcp/500 during lateral"
    },
    {
        "tcp-ike-inventory-exposed-service",
        "tcp",
        500,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ike vpn on tcp/500 during inventory"
    },
    {
        "tcp-ike-inventory-tunnel-or-vpn",
        "tcp",
        500,
        "dst",
        "tunnel-or-vpn",
        "medium",
        "tunneling or VPN service traffic observed: ike vpn on tcp/500 during inventory"
    },
    {
        "tcp-ike-inventory-legacy-compat",
        "tcp",
        500,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ike vpn on tcp/500 during inventory"
    },
    {
        "tcp-ike-admin-plane-exposed-service",
        "tcp",
        500,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ike vpn on tcp/500 during admin-plane"
    },
    {
        "tcp-ike-admin-plane-tunnel-or-vpn",
        "tcp",
        500,
        "dst",
        "tunnel-or-vpn",
        "medium",
        "tunneling or VPN service traffic observed: ike vpn on tcp/500 during admin-plane"
    },
    {
        "tcp-ike-admin-plane-legacy-compat",
        "tcp",
        500,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ike vpn on tcp/500 during admin-plane"
    },
    {
        "udp-ike-ingress-exposed-service",
        "udp",
        500,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ike vpn on udp/500 during ingress"
    },
    {
        "udp-ike-ingress-tunnel-or-vpn",
        "udp",
        500,
        "dst",
        "tunnel-or-vpn",
        "medium",
        "tunneling or VPN service traffic observed: ike vpn on udp/500 during ingress"
    },
    {
        "udp-ike-ingress-legacy-compat",
        "udp",
        500,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ike vpn on udp/500 during ingress"
    },
    {
        "udp-ike-egress-exposed-service",
        "udp",
        500,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ike vpn on udp/500 during egress"
    },
    {
        "udp-ike-egress-tunnel-or-vpn",
        "udp",
        500,
        "dst",
        "tunnel-or-vpn",
        "medium",
        "tunneling or VPN service traffic observed: ike vpn on udp/500 during egress"
    },
    {
        "udp-ike-egress-legacy-compat",
        "udp",
        500,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ike vpn on udp/500 during egress"
    },
    {
        "udp-ike-source-service-exposed-service",
        "udp",
        500,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: ike vpn on udp/500 during source-service"
    },
    {
        "udp-ike-source-service-tunnel-or-vpn",
        "udp",
        500,
        "src",
        "tunnel-or-vpn",
        "medium",
        "tunneling or VPN service traffic observed: ike vpn on udp/500 during source-service"
    },
    {
        "udp-ike-source-service-legacy-compat",
        "udp",
        500,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ike vpn on udp/500 during source-service"
    },
    {
        "udp-ike-lateral-exposed-service",
        "udp",
        500,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ike vpn on udp/500 during lateral"
    },
    {
        "udp-ike-lateral-tunnel-or-vpn",
        "udp",
        500,
        "dst",
        "tunnel-or-vpn",
        "medium",
        "tunneling or VPN service traffic observed: ike vpn on udp/500 during lateral"
    },
    {
        "udp-ike-lateral-legacy-compat",
        "udp",
        500,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ike vpn on udp/500 during lateral"
    },
    {
        "udp-ike-inventory-exposed-service",
        "udp",
        500,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ike vpn on udp/500 during inventory"
    },
    {
        "udp-ike-inventory-tunnel-or-vpn",
        "udp",
        500,
        "dst",
        "tunnel-or-vpn",
        "medium",
        "tunneling or VPN service traffic observed: ike vpn on udp/500 during inventory"
    },
    {
        "udp-ike-inventory-legacy-compat",
        "udp",
        500,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ike vpn on udp/500 during inventory"
    },
    {
        "udp-ike-admin-plane-exposed-service",
        "udp",
        500,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ike vpn on udp/500 during admin-plane"
    },
    {
        "udp-ike-admin-plane-tunnel-or-vpn",
        "udp",
        500,
        "dst",
        "tunnel-or-vpn",
        "medium",
        "tunneling or VPN service traffic observed: ike vpn on udp/500 during admin-plane"
    },
    {
        "udp-ike-admin-plane-legacy-compat",
        "udp",
        500,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ike vpn on udp/500 during admin-plane"
    },
    {
        "tcp-syslog-ingress-exposed-service",
        "tcp",
        514,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: syslog logging on tcp/514 during ingress"
    },
    {
        "tcp-syslog-ingress-cleartext-risk",
        "tcp",
        514,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: syslog logging on tcp/514 during ingress"
    },
    {
        "tcp-syslog-ingress-legacy-compat",
        "tcp",
        514,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: syslog logging on tcp/514 during ingress"
    },
    {
        "tcp-syslog-ingress-monitoring",
        "tcp",
        514,
        "dst",
        "monitoring",
        "low",
        "monitoring or telemetry service observed: syslog logging on tcp/514 during ingress"
    },
    {
        "tcp-syslog-egress-exposed-service",
        "tcp",
        514,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: syslog logging on tcp/514 during egress"
    },
    {
        "tcp-syslog-egress-cleartext-risk",
        "tcp",
        514,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: syslog logging on tcp/514 during egress"
    },
    {
        "tcp-syslog-egress-legacy-compat",
        "tcp",
        514,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: syslog logging on tcp/514 during egress"
    },
    {
        "tcp-syslog-egress-monitoring",
        "tcp",
        514,
        "dst",
        "monitoring",
        "low",
        "monitoring or telemetry service observed: syslog logging on tcp/514 during egress"
    },
    {
        "tcp-syslog-source-service-exposed-service",
        "tcp",
        514,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: syslog logging on tcp/514 during source-service"
    },
    {
        "tcp-syslog-source-service-cleartext-risk",
        "tcp",
        514,
        "src",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: syslog logging on tcp/514 during source-service"
    },
    {
        "tcp-syslog-source-service-legacy-compat",
        "tcp",
        514,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: syslog logging on tcp/514 during source-service"
    },
    {
        "tcp-syslog-source-service-monitoring",
        "tcp",
        514,
        "src",
        "monitoring",
        "low",
        "monitoring or telemetry service observed: syslog logging on tcp/514 during source-service"
    },
    {
        "tcp-syslog-lateral-exposed-service",
        "tcp",
        514,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: syslog logging on tcp/514 during lateral"
    },
    {
        "tcp-syslog-lateral-cleartext-risk",
        "tcp",
        514,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: syslog logging on tcp/514 during lateral"
    },
    {
        "tcp-syslog-lateral-legacy-compat",
        "tcp",
        514,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: syslog logging on tcp/514 during lateral"
    },
    {
        "tcp-syslog-lateral-monitoring",
        "tcp",
        514,
        "dst",
        "monitoring",
        "low",
        "monitoring or telemetry service observed: syslog logging on tcp/514 during lateral"
    },
    {
        "tcp-syslog-inventory-exposed-service",
        "tcp",
        514,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: syslog logging on tcp/514 during inventory"
    },
    {
        "tcp-syslog-inventory-cleartext-risk",
        "tcp",
        514,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: syslog logging on tcp/514 during inventory"
    },
    {
        "tcp-syslog-inventory-legacy-compat",
        "tcp",
        514,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: syslog logging on tcp/514 during inventory"
    },
    {
        "tcp-syslog-inventory-monitoring",
        "tcp",
        514,
        "dst",
        "monitoring",
        "low",
        "monitoring or telemetry service observed: syslog logging on tcp/514 during inventory"
    },
    {
        "tcp-syslog-admin-plane-exposed-service",
        "tcp",
        514,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: syslog logging on tcp/514 during admin-plane"
    },
    {
        "tcp-syslog-admin-plane-cleartext-risk",
        "tcp",
        514,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: syslog logging on tcp/514 during admin-plane"
    },
    {
        "tcp-syslog-admin-plane-legacy-compat",
        "tcp",
        514,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: syslog logging on tcp/514 during admin-plane"
    },
    {
        "tcp-syslog-admin-plane-monitoring",
        "tcp",
        514,
        "dst",
        "monitoring",
        "low",
        "monitoring or telemetry service observed: syslog logging on tcp/514 during admin-plane"
    },
    {
        "udp-syslog-ingress-exposed-service",
        "udp",
        514,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: syslog logging on udp/514 during ingress"
    },
    {
        "udp-syslog-ingress-cleartext-risk",
        "udp",
        514,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: syslog logging on udp/514 during ingress"
    },
    {
        "udp-syslog-ingress-legacy-compat",
        "udp",
        514,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: syslog logging on udp/514 during ingress"
    },
    {
        "udp-syslog-ingress-monitoring",
        "udp",
        514,
        "dst",
        "monitoring",
        "low",
        "monitoring or telemetry service observed: syslog logging on udp/514 during ingress"
    },
    {
        "udp-syslog-egress-exposed-service",
        "udp",
        514,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: syslog logging on udp/514 during egress"
    },
    {
        "udp-syslog-egress-cleartext-risk",
        "udp",
        514,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: syslog logging on udp/514 during egress"
    },
    {
        "udp-syslog-egress-legacy-compat",
        "udp",
        514,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: syslog logging on udp/514 during egress"
    },
    {
        "udp-syslog-egress-monitoring",
        "udp",
        514,
        "dst",
        "monitoring",
        "low",
        "monitoring or telemetry service observed: syslog logging on udp/514 during egress"
    },
    {
        "udp-syslog-source-service-exposed-service",
        "udp",
        514,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: syslog logging on udp/514 during source-service"
    },
    {
        "udp-syslog-source-service-cleartext-risk",
        "udp",
        514,
        "src",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: syslog logging on udp/514 during source-service"
    },
    {
        "udp-syslog-source-service-legacy-compat",
        "udp",
        514,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: syslog logging on udp/514 during source-service"
    },
    {
        "udp-syslog-source-service-monitoring",
        "udp",
        514,
        "src",
        "monitoring",
        "low",
        "monitoring or telemetry service observed: syslog logging on udp/514 during source-service"
    },
    {
        "udp-syslog-lateral-exposed-service",
        "udp",
        514,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: syslog logging on udp/514 during lateral"
    },
    {
        "udp-syslog-lateral-cleartext-risk",
        "udp",
        514,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: syslog logging on udp/514 during lateral"
    },
    {
        "udp-syslog-lateral-legacy-compat",
        "udp",
        514,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: syslog logging on udp/514 during lateral"
    },
    {
        "udp-syslog-lateral-monitoring",
        "udp",
        514,
        "dst",
        "monitoring",
        "low",
        "monitoring or telemetry service observed: syslog logging on udp/514 during lateral"
    },
    {
        "udp-syslog-inventory-exposed-service",
        "udp",
        514,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: syslog logging on udp/514 during inventory"
    },
    {
        "udp-syslog-inventory-cleartext-risk",
        "udp",
        514,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: syslog logging on udp/514 during inventory"
    },
    {
        "udp-syslog-inventory-legacy-compat",
        "udp",
        514,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: syslog logging on udp/514 during inventory"
    },
    {
        "udp-syslog-inventory-monitoring",
        "udp",
        514,
        "dst",
        "monitoring",
        "low",
        "monitoring or telemetry service observed: syslog logging on udp/514 during inventory"
    },
    {
        "udp-syslog-admin-plane-exposed-service",
        "udp",
        514,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: syslog logging on udp/514 during admin-plane"
    },
    {
        "udp-syslog-admin-plane-cleartext-risk",
        "udp",
        514,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: syslog logging on udp/514 during admin-plane"
    },
    {
        "udp-syslog-admin-plane-legacy-compat",
        "udp",
        514,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: syslog logging on udp/514 during admin-plane"
    },
    {
        "udp-syslog-admin-plane-monitoring",
        "udp",
        514,
        "dst",
        "monitoring",
        "low",
        "monitoring or telemetry service observed: syslog logging on udp/514 during admin-plane"
    },
    {
        "tcp-smtp-client-ingress-exposed-service",
        "tcp",
        587,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: smtp-client mail-client on tcp/587 during ingress"
    },
    {
        "tcp-smtp-client-ingress-legacy-compat",
        "tcp",
        587,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: smtp-client mail-client on tcp/587 during ingress"
    },
    {
        "tcp-smtp-client-egress-exposed-service",
        "tcp",
        587,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: smtp-client mail-client on tcp/587 during egress"
    },
    {
        "tcp-smtp-client-egress-legacy-compat",
        "tcp",
        587,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: smtp-client mail-client on tcp/587 during egress"
    },
    {
        "tcp-smtp-client-source-service-exposed-service",
        "tcp",
        587,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: smtp-client mail-client on tcp/587 during source-service"
    },
    {
        "tcp-smtp-client-source-service-legacy-compat",
        "tcp",
        587,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: smtp-client mail-client on tcp/587 during source-service"
    },
    {
        "tcp-smtp-client-lateral-exposed-service",
        "tcp",
        587,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: smtp-client mail-client on tcp/587 during lateral"
    },
    {
        "tcp-smtp-client-lateral-legacy-compat",
        "tcp",
        587,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: smtp-client mail-client on tcp/587 during lateral"
    },
    {
        "tcp-smtp-client-inventory-exposed-service",
        "tcp",
        587,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: smtp-client mail-client on tcp/587 during inventory"
    },
    {
        "tcp-smtp-client-inventory-legacy-compat",
        "tcp",
        587,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: smtp-client mail-client on tcp/587 during inventory"
    },
    {
        "tcp-smtp-client-admin-plane-exposed-service",
        "tcp",
        587,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: smtp-client mail-client on tcp/587 during admin-plane"
    },
    {
        "tcp-smtp-client-admin-plane-legacy-compat",
        "tcp",
        587,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: smtp-client mail-client on tcp/587 during admin-plane"
    },
    {
        "tcp-ldaps-ingress-exposed-service",
        "tcp",
        636,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ldaps directory-tls on tcp/636 during ingress"
    },
    {
        "tcp-ldaps-ingress-identity-plane",
        "tcp",
        636,
        "dst",
        "identity-plane",
        "medium",
        "identity infrastructure traffic observed: ldaps directory-tls on tcp/636 during ingress"
    },
    {
        "tcp-ldaps-ingress-legacy-compat",
        "tcp",
        636,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ldaps directory-tls on tcp/636 during ingress"
    },
    {
        "tcp-ldaps-egress-exposed-service",
        "tcp",
        636,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ldaps directory-tls on tcp/636 during egress"
    },
    {
        "tcp-ldaps-egress-identity-plane",
        "tcp",
        636,
        "dst",
        "identity-plane",
        "medium",
        "identity infrastructure traffic observed: ldaps directory-tls on tcp/636 during egress"
    },
    {
        "tcp-ldaps-egress-legacy-compat",
        "tcp",
        636,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ldaps directory-tls on tcp/636 during egress"
    },
    {
        "tcp-ldaps-source-service-exposed-service",
        "tcp",
        636,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: ldaps directory-tls on tcp/636 during source-service"
    },
    {
        "tcp-ldaps-source-service-identity-plane",
        "tcp",
        636,
        "src",
        "identity-plane",
        "medium",
        "identity infrastructure traffic observed: ldaps directory-tls on tcp/636 during source-service"
    },
    {
        "tcp-ldaps-source-service-legacy-compat",
        "tcp",
        636,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ldaps directory-tls on tcp/636 during source-service"
    },
    {
        "tcp-ldaps-lateral-exposed-service",
        "tcp",
        636,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ldaps directory-tls on tcp/636 during lateral"
    },
    {
        "tcp-ldaps-lateral-identity-plane",
        "tcp",
        636,
        "dst",
        "identity-plane",
        "medium",
        "identity infrastructure traffic observed: ldaps directory-tls on tcp/636 during lateral"
    },
    {
        "tcp-ldaps-lateral-legacy-compat",
        "tcp",
        636,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ldaps directory-tls on tcp/636 during lateral"
    },
    {
        "tcp-ldaps-inventory-exposed-service",
        "tcp",
        636,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ldaps directory-tls on tcp/636 during inventory"
    },
    {
        "tcp-ldaps-inventory-identity-plane",
        "tcp",
        636,
        "dst",
        "identity-plane",
        "medium",
        "identity infrastructure traffic observed: ldaps directory-tls on tcp/636 during inventory"
    },
    {
        "tcp-ldaps-inventory-legacy-compat",
        "tcp",
        636,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ldaps directory-tls on tcp/636 during inventory"
    },
    {
        "tcp-ldaps-admin-plane-exposed-service",
        "tcp",
        636,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: ldaps directory-tls on tcp/636 during admin-plane"
    },
    {
        "tcp-ldaps-admin-plane-identity-plane",
        "tcp",
        636,
        "dst",
        "identity-plane",
        "medium",
        "identity infrastructure traffic observed: ldaps directory-tls on tcp/636 during admin-plane"
    },
    {
        "tcp-ldaps-admin-plane-legacy-compat",
        "tcp",
        636,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: ldaps directory-tls on tcp/636 during admin-plane"
    },
    {
        "tcp-imaps-ingress-exposed-service",
        "tcp",
        993,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: imaps mail-tls on tcp/993 during ingress"
    },
    {
        "tcp-imaps-ingress-legacy-compat",
        "tcp",
        993,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: imaps mail-tls on tcp/993 during ingress"
    },
    {
        "tcp-imaps-egress-exposed-service",
        "tcp",
        993,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: imaps mail-tls on tcp/993 during egress"
    },
    {
        "tcp-imaps-egress-legacy-compat",
        "tcp",
        993,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: imaps mail-tls on tcp/993 during egress"
    },
    {
        "tcp-imaps-source-service-exposed-service",
        "tcp",
        993,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: imaps mail-tls on tcp/993 during source-service"
    },
    {
        "tcp-imaps-source-service-legacy-compat",
        "tcp",
        993,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: imaps mail-tls on tcp/993 during source-service"
    },
    {
        "tcp-imaps-lateral-exposed-service",
        "tcp",
        993,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: imaps mail-tls on tcp/993 during lateral"
    },
    {
        "tcp-imaps-lateral-legacy-compat",
        "tcp",
        993,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: imaps mail-tls on tcp/993 during lateral"
    },
    {
        "tcp-imaps-inventory-exposed-service",
        "tcp",
        993,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: imaps mail-tls on tcp/993 during inventory"
    },
    {
        "tcp-imaps-inventory-legacy-compat",
        "tcp",
        993,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: imaps mail-tls on tcp/993 during inventory"
    },
    {
        "tcp-imaps-admin-plane-exposed-service",
        "tcp",
        993,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: imaps mail-tls on tcp/993 during admin-plane"
    },
    {
        "tcp-imaps-admin-plane-legacy-compat",
        "tcp",
        993,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: imaps mail-tls on tcp/993 during admin-plane"
    },
    {
        "tcp-pop3s-ingress-exposed-service",
        "tcp",
        995,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: pop3s mail-tls on tcp/995 during ingress"
    },
    {
        "tcp-pop3s-ingress-legacy-compat",
        "tcp",
        995,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: pop3s mail-tls on tcp/995 during ingress"
    },
    {
        "tcp-pop3s-egress-exposed-service",
        "tcp",
        995,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: pop3s mail-tls on tcp/995 during egress"
    },
    {
        "tcp-pop3s-egress-legacy-compat",
        "tcp",
        995,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: pop3s mail-tls on tcp/995 during egress"
    },
    {
        "tcp-pop3s-source-service-exposed-service",
        "tcp",
        995,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: pop3s mail-tls on tcp/995 during source-service"
    },
    {
        "tcp-pop3s-source-service-legacy-compat",
        "tcp",
        995,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: pop3s mail-tls on tcp/995 during source-service"
    },
    {
        "tcp-pop3s-lateral-exposed-service",
        "tcp",
        995,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: pop3s mail-tls on tcp/995 during lateral"
    },
    {
        "tcp-pop3s-lateral-legacy-compat",
        "tcp",
        995,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: pop3s mail-tls on tcp/995 during lateral"
    },
    {
        "tcp-pop3s-inventory-exposed-service",
        "tcp",
        995,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: pop3s mail-tls on tcp/995 during inventory"
    },
    {
        "tcp-pop3s-inventory-legacy-compat",
        "tcp",
        995,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: pop3s mail-tls on tcp/995 during inventory"
    },
    {
        "tcp-pop3s-admin-plane-exposed-service",
        "tcp",
        995,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: pop3s mail-tls on tcp/995 during admin-plane"
    },
    {
        "tcp-pop3s-admin-plane-legacy-compat",
        "tcp",
        995,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: pop3s mail-tls on tcp/995 during admin-plane"
    },
    {
        "tcp-mssql-ingress-exposed-service",
        "tcp",
        1433,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: mssql database on tcp/1433 during ingress"
    },
    {
        "tcp-mssql-ingress-data-store",
        "tcp",
        1433,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: mssql database on tcp/1433 during ingress"
    },
    {
        "tcp-mssql-ingress-legacy-compat",
        "tcp",
        1433,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: mssql database on tcp/1433 during ingress"
    },
    {
        "tcp-mssql-egress-exposed-service",
        "tcp",
        1433,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: mssql database on tcp/1433 during egress"
    },
    {
        "tcp-mssql-egress-data-store",
        "tcp",
        1433,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: mssql database on tcp/1433 during egress"
    },
    {
        "tcp-mssql-egress-legacy-compat",
        "tcp",
        1433,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: mssql database on tcp/1433 during egress"
    },
    {
        "tcp-mssql-source-service-exposed-service",
        "tcp",
        1433,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: mssql database on tcp/1433 during source-service"
    },
    {
        "tcp-mssql-source-service-data-store",
        "tcp",
        1433,
        "src",
        "data-store",
        "high",
        "database or cache service traffic observed: mssql database on tcp/1433 during source-service"
    },
    {
        "tcp-mssql-source-service-legacy-compat",
        "tcp",
        1433,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: mssql database on tcp/1433 during source-service"
    },
    {
        "tcp-mssql-lateral-exposed-service",
        "tcp",
        1433,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: mssql database on tcp/1433 during lateral"
    },
    {
        "tcp-mssql-lateral-data-store",
        "tcp",
        1433,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: mssql database on tcp/1433 during lateral"
    },
    {
        "tcp-mssql-lateral-legacy-compat",
        "tcp",
        1433,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: mssql database on tcp/1433 during lateral"
    },
    {
        "tcp-mssql-inventory-exposed-service",
        "tcp",
        1433,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: mssql database on tcp/1433 during inventory"
    },
    {
        "tcp-mssql-inventory-data-store",
        "tcp",
        1433,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: mssql database on tcp/1433 during inventory"
    },
    {
        "tcp-mssql-inventory-legacy-compat",
        "tcp",
        1433,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: mssql database on tcp/1433 during inventory"
    },
    {
        "tcp-mssql-admin-plane-exposed-service",
        "tcp",
        1433,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: mssql database on tcp/1433 during admin-plane"
    },
    {
        "tcp-mssql-admin-plane-data-store",
        "tcp",
        1433,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: mssql database on tcp/1433 during admin-plane"
    },
    {
        "tcp-mssql-admin-plane-legacy-compat",
        "tcp",
        1433,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: mssql database on tcp/1433 during admin-plane"
    },
    {
        "tcp-oracle-ingress-exposed-service",
        "tcp",
        1521,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: oracle database on tcp/1521 during ingress"
    },
    {
        "tcp-oracle-ingress-data-store",
        "tcp",
        1521,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: oracle database on tcp/1521 during ingress"
    },
    {
        "tcp-oracle-ingress-legacy-compat",
        "tcp",
        1521,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: oracle database on tcp/1521 during ingress"
    },
    {
        "tcp-oracle-egress-exposed-service",
        "tcp",
        1521,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: oracle database on tcp/1521 during egress"
    },
    {
        "tcp-oracle-egress-data-store",
        "tcp",
        1521,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: oracle database on tcp/1521 during egress"
    },
    {
        "tcp-oracle-egress-legacy-compat",
        "tcp",
        1521,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: oracle database on tcp/1521 during egress"
    },
    {
        "tcp-oracle-source-service-exposed-service",
        "tcp",
        1521,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: oracle database on tcp/1521 during source-service"
    },
    {
        "tcp-oracle-source-service-data-store",
        "tcp",
        1521,
        "src",
        "data-store",
        "high",
        "database or cache service traffic observed: oracle database on tcp/1521 during source-service"
    },
    {
        "tcp-oracle-source-service-legacy-compat",
        "tcp",
        1521,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: oracle database on tcp/1521 during source-service"
    },
    {
        "tcp-oracle-lateral-exposed-service",
        "tcp",
        1521,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: oracle database on tcp/1521 during lateral"
    },
    {
        "tcp-oracle-lateral-data-store",
        "tcp",
        1521,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: oracle database on tcp/1521 during lateral"
    },
    {
        "tcp-oracle-lateral-legacy-compat",
        "tcp",
        1521,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: oracle database on tcp/1521 during lateral"
    },
    {
        "tcp-oracle-inventory-exposed-service",
        "tcp",
        1521,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: oracle database on tcp/1521 during inventory"
    },
    {
        "tcp-oracle-inventory-data-store",
        "tcp",
        1521,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: oracle database on tcp/1521 during inventory"
    },
    {
        "tcp-oracle-inventory-legacy-compat",
        "tcp",
        1521,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: oracle database on tcp/1521 during inventory"
    },
    {
        "tcp-oracle-admin-plane-exposed-service",
        "tcp",
        1521,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: oracle database on tcp/1521 during admin-plane"
    },
    {
        "tcp-oracle-admin-plane-data-store",
        "tcp",
        1521,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: oracle database on tcp/1521 during admin-plane"
    },
    {
        "tcp-oracle-admin-plane-legacy-compat",
        "tcp",
        1521,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: oracle database on tcp/1521 during admin-plane"
    },
    {
        "tcp-pptp-ingress-exposed-service",
        "tcp",
        1723,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: pptp vpn on tcp/1723 during ingress"
    },
    {
        "tcp-pptp-ingress-tunnel-or-vpn",
        "tcp",
        1723,
        "dst",
        "tunnel-or-vpn",
        "medium",
        "tunneling or VPN service traffic observed: pptp vpn on tcp/1723 during ingress"
    },
    {
        "tcp-pptp-ingress-legacy-compat",
        "tcp",
        1723,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: pptp vpn on tcp/1723 during ingress"
    },
    {
        "tcp-pptp-egress-exposed-service",
        "tcp",
        1723,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: pptp vpn on tcp/1723 during egress"
    },
    {
        "tcp-pptp-egress-tunnel-or-vpn",
        "tcp",
        1723,
        "dst",
        "tunnel-or-vpn",
        "medium",
        "tunneling or VPN service traffic observed: pptp vpn on tcp/1723 during egress"
    },
    {
        "tcp-pptp-egress-legacy-compat",
        "tcp",
        1723,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: pptp vpn on tcp/1723 during egress"
    },
    {
        "tcp-pptp-source-service-exposed-service",
        "tcp",
        1723,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: pptp vpn on tcp/1723 during source-service"
    },
    {
        "tcp-pptp-source-service-tunnel-or-vpn",
        "tcp",
        1723,
        "src",
        "tunnel-or-vpn",
        "medium",
        "tunneling or VPN service traffic observed: pptp vpn on tcp/1723 during source-service"
    },
    {
        "tcp-pptp-source-service-legacy-compat",
        "tcp",
        1723,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: pptp vpn on tcp/1723 during source-service"
    },
    {
        "tcp-pptp-lateral-exposed-service",
        "tcp",
        1723,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: pptp vpn on tcp/1723 during lateral"
    },
    {
        "tcp-pptp-lateral-tunnel-or-vpn",
        "tcp",
        1723,
        "dst",
        "tunnel-or-vpn",
        "medium",
        "tunneling or VPN service traffic observed: pptp vpn on tcp/1723 during lateral"
    },
    {
        "tcp-pptp-lateral-legacy-compat",
        "tcp",
        1723,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: pptp vpn on tcp/1723 during lateral"
    },
    {
        "tcp-pptp-inventory-exposed-service",
        "tcp",
        1723,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: pptp vpn on tcp/1723 during inventory"
    },
    {
        "tcp-pptp-inventory-tunnel-or-vpn",
        "tcp",
        1723,
        "dst",
        "tunnel-or-vpn",
        "medium",
        "tunneling or VPN service traffic observed: pptp vpn on tcp/1723 during inventory"
    },
    {
        "tcp-pptp-inventory-legacy-compat",
        "tcp",
        1723,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: pptp vpn on tcp/1723 during inventory"
    },
    {
        "tcp-pptp-admin-plane-exposed-service",
        "tcp",
        1723,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: pptp vpn on tcp/1723 during admin-plane"
    },
    {
        "tcp-pptp-admin-plane-tunnel-or-vpn",
        "tcp",
        1723,
        "dst",
        "tunnel-or-vpn",
        "medium",
        "tunneling or VPN service traffic observed: pptp vpn on tcp/1723 during admin-plane"
    },
    {
        "tcp-pptp-admin-plane-legacy-compat",
        "tcp",
        1723,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: pptp vpn on tcp/1723 during admin-plane"
    },
    {
        "tcp-nfs-ingress-exposed-service",
        "tcp",
        2049,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: nfs file-sharing on tcp/2049 during ingress"
    },
    {
        "tcp-nfs-ingress-legacy-compat",
        "tcp",
        2049,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: nfs file-sharing on tcp/2049 during ingress"
    },
    {
        "tcp-nfs-egress-exposed-service",
        "tcp",
        2049,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: nfs file-sharing on tcp/2049 during egress"
    },
    {
        "tcp-nfs-egress-legacy-compat",
        "tcp",
        2049,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: nfs file-sharing on tcp/2049 during egress"
    },
    {
        "tcp-nfs-source-service-exposed-service",
        "tcp",
        2049,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: nfs file-sharing on tcp/2049 during source-service"
    },
    {
        "tcp-nfs-source-service-legacy-compat",
        "tcp",
        2049,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: nfs file-sharing on tcp/2049 during source-service"
    },
    {
        "tcp-nfs-lateral-exposed-service",
        "tcp",
        2049,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: nfs file-sharing on tcp/2049 during lateral"
    },
    {
        "tcp-nfs-lateral-legacy-compat",
        "tcp",
        2049,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: nfs file-sharing on tcp/2049 during lateral"
    },
    {
        "tcp-nfs-inventory-exposed-service",
        "tcp",
        2049,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: nfs file-sharing on tcp/2049 during inventory"
    },
    {
        "tcp-nfs-inventory-legacy-compat",
        "tcp",
        2049,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: nfs file-sharing on tcp/2049 during inventory"
    },
    {
        "tcp-nfs-admin-plane-exposed-service",
        "tcp",
        2049,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: nfs file-sharing on tcp/2049 during admin-plane"
    },
    {
        "tcp-nfs-admin-plane-legacy-compat",
        "tcp",
        2049,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: nfs file-sharing on tcp/2049 during admin-plane"
    },
    {
        "tcp-docker-ingress-exposed-service",
        "tcp",
        2375,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: docker container-api on tcp/2375 during ingress"
    },
    {
        "tcp-docker-ingress-cleartext-risk",
        "tcp",
        2375,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: docker container-api on tcp/2375 during ingress"
    },
    {
        "tcp-docker-ingress-management-plane",
        "tcp",
        2375,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: docker container-api on tcp/2375 during ingress"
    },
    {
        "tcp-docker-ingress-legacy-compat",
        "tcp",
        2375,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: docker container-api on tcp/2375 during ingress"
    },
    {
        "tcp-docker-egress-exposed-service",
        "tcp",
        2375,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: docker container-api on tcp/2375 during egress"
    },
    {
        "tcp-docker-egress-cleartext-risk",
        "tcp",
        2375,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: docker container-api on tcp/2375 during egress"
    },
    {
        "tcp-docker-egress-management-plane",
        "tcp",
        2375,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: docker container-api on tcp/2375 during egress"
    },
    {
        "tcp-docker-egress-legacy-compat",
        "tcp",
        2375,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: docker container-api on tcp/2375 during egress"
    },
    {
        "tcp-docker-source-service-exposed-service",
        "tcp",
        2375,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: docker container-api on tcp/2375 during source-service"
    },
    {
        "tcp-docker-source-service-cleartext-risk",
        "tcp",
        2375,
        "src",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: docker container-api on tcp/2375 during source-service"
    },
    {
        "tcp-docker-source-service-management-plane",
        "tcp",
        2375,
        "src",
        "management-plane",
        "high",
        "management interface traffic observed: docker container-api on tcp/2375 during source-service"
    },
    {
        "tcp-docker-source-service-legacy-compat",
        "tcp",
        2375,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: docker container-api on tcp/2375 during source-service"
    },
    {
        "tcp-docker-lateral-exposed-service",
        "tcp",
        2375,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: docker container-api on tcp/2375 during lateral"
    },
    {
        "tcp-docker-lateral-cleartext-risk",
        "tcp",
        2375,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: docker container-api on tcp/2375 during lateral"
    },
    {
        "tcp-docker-lateral-management-plane",
        "tcp",
        2375,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: docker container-api on tcp/2375 during lateral"
    },
    {
        "tcp-docker-lateral-legacy-compat",
        "tcp",
        2375,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: docker container-api on tcp/2375 during lateral"
    },
    {
        "tcp-docker-inventory-exposed-service",
        "tcp",
        2375,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: docker container-api on tcp/2375 during inventory"
    },
    {
        "tcp-docker-inventory-cleartext-risk",
        "tcp",
        2375,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: docker container-api on tcp/2375 during inventory"
    },
    {
        "tcp-docker-inventory-management-plane",
        "tcp",
        2375,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: docker container-api on tcp/2375 during inventory"
    },
    {
        "tcp-docker-inventory-legacy-compat",
        "tcp",
        2375,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: docker container-api on tcp/2375 during inventory"
    },
    {
        "tcp-docker-admin-plane-exposed-service",
        "tcp",
        2375,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: docker container-api on tcp/2375 during admin-plane"
    },
    {
        "tcp-docker-admin-plane-cleartext-risk",
        "tcp",
        2375,
        "dst",
        "cleartext-risk",
        "high",
        "cleartext or weakly authenticated service observed: docker container-api on tcp/2375 during admin-plane"
    },
    {
        "tcp-docker-admin-plane-management-plane",
        "tcp",
        2375,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: docker container-api on tcp/2375 during admin-plane"
    },
    {
        "tcp-docker-admin-plane-legacy-compat",
        "tcp",
        2375,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: docker container-api on tcp/2375 during admin-plane"
    },
    {
        "tcp-docker-tls-ingress-exposed-service",
        "tcp",
        2376,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: docker-tls container-api on tcp/2376 during ingress"
    },
    {
        "tcp-docker-tls-ingress-management-plane",
        "tcp",
        2376,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: docker-tls container-api on tcp/2376 during ingress"
    },
    {
        "tcp-docker-tls-ingress-legacy-compat",
        "tcp",
        2376,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: docker-tls container-api on tcp/2376 during ingress"
    },
    {
        "tcp-docker-tls-egress-exposed-service",
        "tcp",
        2376,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: docker-tls container-api on tcp/2376 during egress"
    },
    {
        "tcp-docker-tls-egress-management-plane",
        "tcp",
        2376,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: docker-tls container-api on tcp/2376 during egress"
    },
    {
        "tcp-docker-tls-egress-legacy-compat",
        "tcp",
        2376,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: docker-tls container-api on tcp/2376 during egress"
    },
    {
        "tcp-docker-tls-source-service-exposed-service",
        "tcp",
        2376,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: docker-tls container-api on tcp/2376 during source-service"
    },
    {
        "tcp-docker-tls-source-service-management-plane",
        "tcp",
        2376,
        "src",
        "management-plane",
        "high",
        "management interface traffic observed: docker-tls container-api on tcp/2376 during source-service"
    },
    {
        "tcp-docker-tls-source-service-legacy-compat",
        "tcp",
        2376,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: docker-tls container-api on tcp/2376 during source-service"
    },
    {
        "tcp-docker-tls-lateral-exposed-service",
        "tcp",
        2376,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: docker-tls container-api on tcp/2376 during lateral"
    },
    {
        "tcp-docker-tls-lateral-management-plane",
        "tcp",
        2376,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: docker-tls container-api on tcp/2376 during lateral"
    },
    {
        "tcp-docker-tls-lateral-legacy-compat",
        "tcp",
        2376,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: docker-tls container-api on tcp/2376 during lateral"
    },
    {
        "tcp-docker-tls-inventory-exposed-service",
        "tcp",
        2376,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: docker-tls container-api on tcp/2376 during inventory"
    },
    {
        "tcp-docker-tls-inventory-management-plane",
        "tcp",
        2376,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: docker-tls container-api on tcp/2376 during inventory"
    },
    {
        "tcp-docker-tls-inventory-legacy-compat",
        "tcp",
        2376,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: docker-tls container-api on tcp/2376 during inventory"
    },
    {
        "tcp-docker-tls-admin-plane-exposed-service",
        "tcp",
        2376,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: docker-tls container-api on tcp/2376 during admin-plane"
    },
    {
        "tcp-docker-tls-admin-plane-management-plane",
        "tcp",
        2376,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: docker-tls container-api on tcp/2376 during admin-plane"
    },
    {
        "tcp-docker-tls-admin-plane-legacy-compat",
        "tcp",
        2376,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: docker-tls container-api on tcp/2376 during admin-plane"
    },
    {
        "tcp-mysql-ingress-exposed-service",
        "tcp",
        3306,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: mysql database on tcp/3306 during ingress"
    },
    {
        "tcp-mysql-ingress-data-store",
        "tcp",
        3306,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: mysql database on tcp/3306 during ingress"
    },
    {
        "tcp-mysql-ingress-legacy-compat",
        "tcp",
        3306,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: mysql database on tcp/3306 during ingress"
    },
    {
        "tcp-mysql-egress-exposed-service",
        "tcp",
        3306,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: mysql database on tcp/3306 during egress"
    },
    {
        "tcp-mysql-egress-data-store",
        "tcp",
        3306,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: mysql database on tcp/3306 during egress"
    },
    {
        "tcp-mysql-egress-legacy-compat",
        "tcp",
        3306,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: mysql database on tcp/3306 during egress"
    },
    {
        "tcp-mysql-source-service-exposed-service",
        "tcp",
        3306,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: mysql database on tcp/3306 during source-service"
    },
    {
        "tcp-mysql-source-service-data-store",
        "tcp",
        3306,
        "src",
        "data-store",
        "high",
        "database or cache service traffic observed: mysql database on tcp/3306 during source-service"
    },
    {
        "tcp-mysql-source-service-legacy-compat",
        "tcp",
        3306,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: mysql database on tcp/3306 during source-service"
    },
    {
        "tcp-mysql-lateral-exposed-service",
        "tcp",
        3306,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: mysql database on tcp/3306 during lateral"
    },
    {
        "tcp-mysql-lateral-data-store",
        "tcp",
        3306,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: mysql database on tcp/3306 during lateral"
    },
    {
        "tcp-mysql-lateral-legacy-compat",
        "tcp",
        3306,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: mysql database on tcp/3306 during lateral"
    },
    {
        "tcp-mysql-inventory-exposed-service",
        "tcp",
        3306,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: mysql database on tcp/3306 during inventory"
    },
    {
        "tcp-mysql-inventory-data-store",
        "tcp",
        3306,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: mysql database on tcp/3306 during inventory"
    },
    {
        "tcp-mysql-inventory-legacy-compat",
        "tcp",
        3306,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: mysql database on tcp/3306 during inventory"
    },
    {
        "tcp-mysql-admin-plane-exposed-service",
        "tcp",
        3306,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: mysql database on tcp/3306 during admin-plane"
    },
    {
        "tcp-mysql-admin-plane-data-store",
        "tcp",
        3306,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: mysql database on tcp/3306 during admin-plane"
    },
    {
        "tcp-mysql-admin-plane-legacy-compat",
        "tcp",
        3306,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: mysql database on tcp/3306 during admin-plane"
    },
    {
        "tcp-rdp-ingress-exposed-service",
        "tcp",
        3389,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: rdp remote-admin on tcp/3389 during ingress"
    },
    {
        "tcp-rdp-ingress-management-plane",
        "tcp",
        3389,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: rdp remote-admin on tcp/3389 during ingress"
    },
    {
        "tcp-rdp-ingress-legacy-compat",
        "tcp",
        3389,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: rdp remote-admin on tcp/3389 during ingress"
    },
    {
        "tcp-rdp-egress-exposed-service",
        "tcp",
        3389,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: rdp remote-admin on tcp/3389 during egress"
    },
    {
        "tcp-rdp-egress-management-plane",
        "tcp",
        3389,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: rdp remote-admin on tcp/3389 during egress"
    },
    {
        "tcp-rdp-egress-legacy-compat",
        "tcp",
        3389,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: rdp remote-admin on tcp/3389 during egress"
    },
    {
        "tcp-rdp-source-service-exposed-service",
        "tcp",
        3389,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: rdp remote-admin on tcp/3389 during source-service"
    },
    {
        "tcp-rdp-source-service-management-plane",
        "tcp",
        3389,
        "src",
        "management-plane",
        "high",
        "management interface traffic observed: rdp remote-admin on tcp/3389 during source-service"
    },
    {
        "tcp-rdp-source-service-legacy-compat",
        "tcp",
        3389,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: rdp remote-admin on tcp/3389 during source-service"
    },
    {
        "tcp-rdp-lateral-exposed-service",
        "tcp",
        3389,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: rdp remote-admin on tcp/3389 during lateral"
    },
    {
        "tcp-rdp-lateral-management-plane",
        "tcp",
        3389,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: rdp remote-admin on tcp/3389 during lateral"
    },
    {
        "tcp-rdp-lateral-legacy-compat",
        "tcp",
        3389,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: rdp remote-admin on tcp/3389 during lateral"
    },
    {
        "tcp-rdp-inventory-exposed-service",
        "tcp",
        3389,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: rdp remote-admin on tcp/3389 during inventory"
    },
    {
        "tcp-rdp-inventory-management-plane",
        "tcp",
        3389,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: rdp remote-admin on tcp/3389 during inventory"
    },
    {
        "tcp-rdp-inventory-legacy-compat",
        "tcp",
        3389,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: rdp remote-admin on tcp/3389 during inventory"
    },
    {
        "tcp-rdp-admin-plane-exposed-service",
        "tcp",
        3389,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: rdp remote-admin on tcp/3389 during admin-plane"
    },
    {
        "tcp-rdp-admin-plane-management-plane",
        "tcp",
        3389,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: rdp remote-admin on tcp/3389 during admin-plane"
    },
    {
        "tcp-rdp-admin-plane-legacy-compat",
        "tcp",
        3389,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: rdp remote-admin on tcp/3389 during admin-plane"
    },
    {
        "tcp-operator-console-ingress-exposed-service",
        "tcp",
        4444,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: operator-console remote-control on tcp/4444 during ingress"
    },
    {
        "tcp-operator-console-ingress-legacy-compat",
        "tcp",
        4444,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: operator-console remote-control on tcp/4444 during ingress"
    },
    {
        "tcp-operator-console-egress-exposed-service",
        "tcp",
        4444,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: operator-console remote-control on tcp/4444 during egress"
    },
    {
        "tcp-operator-console-egress-legacy-compat",
        "tcp",
        4444,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: operator-console remote-control on tcp/4444 during egress"
    },
    {
        "tcp-operator-console-source-service-exposed-service",
        "tcp",
        4444,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: operator-console remote-control on tcp/4444 during source-service"
    },
    {
        "tcp-operator-console-source-service-legacy-compat",
        "tcp",
        4444,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: operator-console remote-control on tcp/4444 during source-service"
    },
    {
        "tcp-operator-console-lateral-exposed-service",
        "tcp",
        4444,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: operator-console remote-control on tcp/4444 during lateral"
    },
    {
        "tcp-operator-console-lateral-legacy-compat",
        "tcp",
        4444,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: operator-console remote-control on tcp/4444 during lateral"
    },
    {
        "tcp-operator-console-inventory-exposed-service",
        "tcp",
        4444,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: operator-console remote-control on tcp/4444 during inventory"
    },
    {
        "tcp-operator-console-inventory-legacy-compat",
        "tcp",
        4444,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: operator-console remote-control on tcp/4444 during inventory"
    },
    {
        "tcp-operator-console-admin-plane-exposed-service",
        "tcp",
        4444,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: operator-console remote-control on tcp/4444 during admin-plane"
    },
    {
        "tcp-operator-console-admin-plane-legacy-compat",
        "tcp",
        4444,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: operator-console remote-control on tcp/4444 during admin-plane"
    },
    {
        "tcp-postgres-ingress-exposed-service",
        "tcp",
        5432,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: postgres database on tcp/5432 during ingress"
    },
    {
        "tcp-postgres-ingress-data-store",
        "tcp",
        5432,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: postgres database on tcp/5432 during ingress"
    },
    {
        "tcp-postgres-ingress-legacy-compat",
        "tcp",
        5432,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: postgres database on tcp/5432 during ingress"
    },
    {
        "tcp-postgres-egress-exposed-service",
        "tcp",
        5432,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: postgres database on tcp/5432 during egress"
    },
    {
        "tcp-postgres-egress-data-store",
        "tcp",
        5432,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: postgres database on tcp/5432 during egress"
    },
    {
        "tcp-postgres-egress-legacy-compat",
        "tcp",
        5432,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: postgres database on tcp/5432 during egress"
    },
    {
        "tcp-postgres-source-service-exposed-service",
        "tcp",
        5432,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: postgres database on tcp/5432 during source-service"
    },
    {
        "tcp-postgres-source-service-data-store",
        "tcp",
        5432,
        "src",
        "data-store",
        "high",
        "database or cache service traffic observed: postgres database on tcp/5432 during source-service"
    },
    {
        "tcp-postgres-source-service-legacy-compat",
        "tcp",
        5432,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: postgres database on tcp/5432 during source-service"
    },
    {
        "tcp-postgres-lateral-exposed-service",
        "tcp",
        5432,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: postgres database on tcp/5432 during lateral"
    },
    {
        "tcp-postgres-lateral-data-store",
        "tcp",
        5432,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: postgres database on tcp/5432 during lateral"
    },
    {
        "tcp-postgres-lateral-legacy-compat",
        "tcp",
        5432,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: postgres database on tcp/5432 during lateral"
    },
    {
        "tcp-postgres-inventory-exposed-service",
        "tcp",
        5432,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: postgres database on tcp/5432 during inventory"
    },
    {
        "tcp-postgres-inventory-data-store",
        "tcp",
        5432,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: postgres database on tcp/5432 during inventory"
    },
    {
        "tcp-postgres-inventory-legacy-compat",
        "tcp",
        5432,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: postgres database on tcp/5432 during inventory"
    },
    {
        "tcp-postgres-admin-plane-exposed-service",
        "tcp",
        5432,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: postgres database on tcp/5432 during admin-plane"
    },
    {
        "tcp-postgres-admin-plane-data-store",
        "tcp",
        5432,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: postgres database on tcp/5432 during admin-plane"
    },
    {
        "tcp-postgres-admin-plane-legacy-compat",
        "tcp",
        5432,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: postgres database on tcp/5432 during admin-plane"
    },
    {
        "tcp-kibana-ingress-exposed-service",
        "tcp",
        5601,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: kibana admin-console on tcp/5601 during ingress"
    },
    {
        "tcp-kibana-ingress-management-plane",
        "tcp",
        5601,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: kibana admin-console on tcp/5601 during ingress"
    },
    {
        "tcp-kibana-ingress-legacy-compat",
        "tcp",
        5601,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: kibana admin-console on tcp/5601 during ingress"
    },
    {
        "tcp-kibana-egress-exposed-service",
        "tcp",
        5601,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: kibana admin-console on tcp/5601 during egress"
    },
    {
        "tcp-kibana-egress-management-plane",
        "tcp",
        5601,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: kibana admin-console on tcp/5601 during egress"
    },
    {
        "tcp-kibana-egress-legacy-compat",
        "tcp",
        5601,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: kibana admin-console on tcp/5601 during egress"
    },
    {
        "tcp-kibana-source-service-exposed-service",
        "tcp",
        5601,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: kibana admin-console on tcp/5601 during source-service"
    },
    {
        "tcp-kibana-source-service-management-plane",
        "tcp",
        5601,
        "src",
        "management-plane",
        "high",
        "management interface traffic observed: kibana admin-console on tcp/5601 during source-service"
    },
    {
        "tcp-kibana-source-service-legacy-compat",
        "tcp",
        5601,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: kibana admin-console on tcp/5601 during source-service"
    },
    {
        "tcp-kibana-lateral-exposed-service",
        "tcp",
        5601,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: kibana admin-console on tcp/5601 during lateral"
    },
    {
        "tcp-kibana-lateral-management-plane",
        "tcp",
        5601,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: kibana admin-console on tcp/5601 during lateral"
    },
    {
        "tcp-kibana-lateral-legacy-compat",
        "tcp",
        5601,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: kibana admin-console on tcp/5601 during lateral"
    },
    {
        "tcp-kibana-inventory-exposed-service",
        "tcp",
        5601,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: kibana admin-console on tcp/5601 during inventory"
    },
    {
        "tcp-kibana-inventory-management-plane",
        "tcp",
        5601,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: kibana admin-console on tcp/5601 during inventory"
    },
    {
        "tcp-kibana-inventory-legacy-compat",
        "tcp",
        5601,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: kibana admin-console on tcp/5601 during inventory"
    },
    {
        "tcp-kibana-admin-plane-exposed-service",
        "tcp",
        5601,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: kibana admin-console on tcp/5601 during admin-plane"
    },
    {
        "tcp-kibana-admin-plane-management-plane",
        "tcp",
        5601,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: kibana admin-console on tcp/5601 during admin-plane"
    },
    {
        "tcp-kibana-admin-plane-legacy-compat",
        "tcp",
        5601,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: kibana admin-console on tcp/5601 during admin-plane"
    },
    {
        "tcp-amqp-ingress-exposed-service",
        "tcp",
        5672,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: amqp message-bus on tcp/5672 during ingress"
    },
    {
        "tcp-amqp-ingress-legacy-compat",
        "tcp",
        5672,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: amqp message-bus on tcp/5672 during ingress"
    },
    {
        "tcp-amqp-egress-exposed-service",
        "tcp",
        5672,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: amqp message-bus on tcp/5672 during egress"
    },
    {
        "tcp-amqp-egress-legacy-compat",
        "tcp",
        5672,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: amqp message-bus on tcp/5672 during egress"
    },
    {
        "tcp-amqp-source-service-exposed-service",
        "tcp",
        5672,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: amqp message-bus on tcp/5672 during source-service"
    },
    {
        "tcp-amqp-source-service-legacy-compat",
        "tcp",
        5672,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: amqp message-bus on tcp/5672 during source-service"
    },
    {
        "tcp-amqp-lateral-exposed-service",
        "tcp",
        5672,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: amqp message-bus on tcp/5672 during lateral"
    },
    {
        "tcp-amqp-lateral-legacy-compat",
        "tcp",
        5672,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: amqp message-bus on tcp/5672 during lateral"
    },
    {
        "tcp-amqp-inventory-exposed-service",
        "tcp",
        5672,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: amqp message-bus on tcp/5672 during inventory"
    },
    {
        "tcp-amqp-inventory-legacy-compat",
        "tcp",
        5672,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: amqp message-bus on tcp/5672 during inventory"
    },
    {
        "tcp-amqp-admin-plane-exposed-service",
        "tcp",
        5672,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: amqp message-bus on tcp/5672 during admin-plane"
    },
    {
        "tcp-amqp-admin-plane-legacy-compat",
        "tcp",
        5672,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: amqp message-bus on tcp/5672 during admin-plane"
    },
    {
        "tcp-vnc-ingress-exposed-service",
        "tcp",
        5900,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: vnc remote-admin on tcp/5900 during ingress"
    },
    {
        "tcp-vnc-ingress-management-plane",
        "tcp",
        5900,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: vnc remote-admin on tcp/5900 during ingress"
    },
    {
        "tcp-vnc-ingress-legacy-compat",
        "tcp",
        5900,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: vnc remote-admin on tcp/5900 during ingress"
    },
    {
        "tcp-vnc-egress-exposed-service",
        "tcp",
        5900,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: vnc remote-admin on tcp/5900 during egress"
    },
    {
        "tcp-vnc-egress-management-plane",
        "tcp",
        5900,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: vnc remote-admin on tcp/5900 during egress"
    },
    {
        "tcp-vnc-egress-legacy-compat",
        "tcp",
        5900,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: vnc remote-admin on tcp/5900 during egress"
    },
    {
        "tcp-vnc-source-service-exposed-service",
        "tcp",
        5900,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: vnc remote-admin on tcp/5900 during source-service"
    },
    {
        "tcp-vnc-source-service-management-plane",
        "tcp",
        5900,
        "src",
        "management-plane",
        "high",
        "management interface traffic observed: vnc remote-admin on tcp/5900 during source-service"
    },
    {
        "tcp-vnc-source-service-legacy-compat",
        "tcp",
        5900,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: vnc remote-admin on tcp/5900 during source-service"
    },
    {
        "tcp-vnc-lateral-exposed-service",
        "tcp",
        5900,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: vnc remote-admin on tcp/5900 during lateral"
    },
    {
        "tcp-vnc-lateral-management-plane",
        "tcp",
        5900,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: vnc remote-admin on tcp/5900 during lateral"
    },
    {
        "tcp-vnc-lateral-legacy-compat",
        "tcp",
        5900,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: vnc remote-admin on tcp/5900 during lateral"
    },
    {
        "tcp-vnc-inventory-exposed-service",
        "tcp",
        5900,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: vnc remote-admin on tcp/5900 during inventory"
    },
    {
        "tcp-vnc-inventory-management-plane",
        "tcp",
        5900,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: vnc remote-admin on tcp/5900 during inventory"
    },
    {
        "tcp-vnc-inventory-legacy-compat",
        "tcp",
        5900,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: vnc remote-admin on tcp/5900 during inventory"
    },
    {
        "tcp-vnc-admin-plane-exposed-service",
        "tcp",
        5900,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: vnc remote-admin on tcp/5900 during admin-plane"
    },
    {
        "tcp-vnc-admin-plane-management-plane",
        "tcp",
        5900,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: vnc remote-admin on tcp/5900 during admin-plane"
    },
    {
        "tcp-vnc-admin-plane-legacy-compat",
        "tcp",
        5900,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: vnc remote-admin on tcp/5900 during admin-plane"
    },
    {
        "tcp-winrm-ingress-exposed-service",
        "tcp",
        5985,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: winrm remote-admin on tcp/5985 during ingress"
    },
    {
        "tcp-winrm-ingress-management-plane",
        "tcp",
        5985,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: winrm remote-admin on tcp/5985 during ingress"
    },
    {
        "tcp-winrm-ingress-legacy-compat",
        "tcp",
        5985,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: winrm remote-admin on tcp/5985 during ingress"
    },
    {
        "tcp-winrm-egress-exposed-service",
        "tcp",
        5985,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: winrm remote-admin on tcp/5985 during egress"
    },
    {
        "tcp-winrm-egress-management-plane",
        "tcp",
        5985,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: winrm remote-admin on tcp/5985 during egress"
    },
    {
        "tcp-winrm-egress-legacy-compat",
        "tcp",
        5985,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: winrm remote-admin on tcp/5985 during egress"
    },
    {
        "tcp-winrm-source-service-exposed-service",
        "tcp",
        5985,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: winrm remote-admin on tcp/5985 during source-service"
    },
    {
        "tcp-winrm-source-service-management-plane",
        "tcp",
        5985,
        "src",
        "management-plane",
        "high",
        "management interface traffic observed: winrm remote-admin on tcp/5985 during source-service"
    },
    {
        "tcp-winrm-source-service-legacy-compat",
        "tcp",
        5985,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: winrm remote-admin on tcp/5985 during source-service"
    },
    {
        "tcp-winrm-lateral-exposed-service",
        "tcp",
        5985,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: winrm remote-admin on tcp/5985 during lateral"
    },
    {
        "tcp-winrm-lateral-management-plane",
        "tcp",
        5985,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: winrm remote-admin on tcp/5985 during lateral"
    },
    {
        "tcp-winrm-lateral-legacy-compat",
        "tcp",
        5985,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: winrm remote-admin on tcp/5985 during lateral"
    },
    {
        "tcp-winrm-inventory-exposed-service",
        "tcp",
        5985,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: winrm remote-admin on tcp/5985 during inventory"
    },
    {
        "tcp-winrm-inventory-management-plane",
        "tcp",
        5985,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: winrm remote-admin on tcp/5985 during inventory"
    },
    {
        "tcp-winrm-inventory-legacy-compat",
        "tcp",
        5985,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: winrm remote-admin on tcp/5985 during inventory"
    },
    {
        "tcp-winrm-admin-plane-exposed-service",
        "tcp",
        5985,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: winrm remote-admin on tcp/5985 during admin-plane"
    },
    {
        "tcp-winrm-admin-plane-management-plane",
        "tcp",
        5985,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: winrm remote-admin on tcp/5985 during admin-plane"
    },
    {
        "tcp-winrm-admin-plane-legacy-compat",
        "tcp",
        5985,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: winrm remote-admin on tcp/5985 during admin-plane"
    },
    {
        "tcp-winrm-tls-ingress-exposed-service",
        "tcp",
        5986,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: winrm-tls remote-admin on tcp/5986 during ingress"
    },
    {
        "tcp-winrm-tls-ingress-management-plane",
        "tcp",
        5986,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: winrm-tls remote-admin on tcp/5986 during ingress"
    },
    {
        "tcp-winrm-tls-ingress-legacy-compat",
        "tcp",
        5986,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: winrm-tls remote-admin on tcp/5986 during ingress"
    },
    {
        "tcp-winrm-tls-egress-exposed-service",
        "tcp",
        5986,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: winrm-tls remote-admin on tcp/5986 during egress"
    },
    {
        "tcp-winrm-tls-egress-management-plane",
        "tcp",
        5986,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: winrm-tls remote-admin on tcp/5986 during egress"
    },
    {
        "tcp-winrm-tls-egress-legacy-compat",
        "tcp",
        5986,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: winrm-tls remote-admin on tcp/5986 during egress"
    },
    {
        "tcp-winrm-tls-source-service-exposed-service",
        "tcp",
        5986,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: winrm-tls remote-admin on tcp/5986 during source-service"
    },
    {
        "tcp-winrm-tls-source-service-management-plane",
        "tcp",
        5986,
        "src",
        "management-plane",
        "high",
        "management interface traffic observed: winrm-tls remote-admin on tcp/5986 during source-service"
    },
    {
        "tcp-winrm-tls-source-service-legacy-compat",
        "tcp",
        5986,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: winrm-tls remote-admin on tcp/5986 during source-service"
    },
    {
        "tcp-winrm-tls-lateral-exposed-service",
        "tcp",
        5986,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: winrm-tls remote-admin on tcp/5986 during lateral"
    },
    {
        "tcp-winrm-tls-lateral-management-plane",
        "tcp",
        5986,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: winrm-tls remote-admin on tcp/5986 during lateral"
    },
    {
        "tcp-winrm-tls-lateral-legacy-compat",
        "tcp",
        5986,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: winrm-tls remote-admin on tcp/5986 during lateral"
    },
    {
        "tcp-winrm-tls-inventory-exposed-service",
        "tcp",
        5986,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: winrm-tls remote-admin on tcp/5986 during inventory"
    },
    {
        "tcp-winrm-tls-inventory-management-plane",
        "tcp",
        5986,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: winrm-tls remote-admin on tcp/5986 during inventory"
    },
    {
        "tcp-winrm-tls-inventory-legacy-compat",
        "tcp",
        5986,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: winrm-tls remote-admin on tcp/5986 during inventory"
    },
    {
        "tcp-winrm-tls-admin-plane-exposed-service",
        "tcp",
        5986,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: winrm-tls remote-admin on tcp/5986 during admin-plane"
    },
    {
        "tcp-winrm-tls-admin-plane-management-plane",
        "tcp",
        5986,
        "dst",
        "management-plane",
        "high",
        "management interface traffic observed: winrm-tls remote-admin on tcp/5986 during admin-plane"
    },
    {
        "tcp-winrm-tls-admin-plane-legacy-compat",
        "tcp",
        5986,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: winrm-tls remote-admin on tcp/5986 during admin-plane"
    },
    {
        "tcp-redis-ingress-exposed-service",
        "tcp",
        6379,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: redis database-cache on tcp/6379 during ingress"
    },
    {
        "tcp-redis-ingress-data-store",
        "tcp",
        6379,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: redis database-cache on tcp/6379 during ingress"
    },
    {
        "tcp-redis-ingress-legacy-compat",
        "tcp",
        6379,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: redis database-cache on tcp/6379 during ingress"
    },
    {
        "tcp-redis-egress-exposed-service",
        "tcp",
        6379,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: redis database-cache on tcp/6379 during egress"
    },
    {
        "tcp-redis-egress-data-store",
        "tcp",
        6379,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: redis database-cache on tcp/6379 during egress"
    },
    {
        "tcp-redis-egress-legacy-compat",
        "tcp",
        6379,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: redis database-cache on tcp/6379 during egress"
    },
    {
        "tcp-redis-source-service-exposed-service",
        "tcp",
        6379,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: redis database-cache on tcp/6379 during source-service"
    },
    {
        "tcp-redis-source-service-data-store",
        "tcp",
        6379,
        "src",
        "data-store",
        "high",
        "database or cache service traffic observed: redis database-cache on tcp/6379 during source-service"
    },
    {
        "tcp-redis-source-service-legacy-compat",
        "tcp",
        6379,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: redis database-cache on tcp/6379 during source-service"
    },
    {
        "tcp-redis-lateral-exposed-service",
        "tcp",
        6379,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: redis database-cache on tcp/6379 during lateral"
    },
    {
        "tcp-redis-lateral-data-store",
        "tcp",
        6379,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: redis database-cache on tcp/6379 during lateral"
    },
    {
        "tcp-redis-lateral-legacy-compat",
        "tcp",
        6379,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: redis database-cache on tcp/6379 during lateral"
    },
    {
        "tcp-redis-inventory-exposed-service",
        "tcp",
        6379,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: redis database-cache on tcp/6379 during inventory"
    },
    {
        "tcp-redis-inventory-data-store",
        "tcp",
        6379,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: redis database-cache on tcp/6379 during inventory"
    },
    {
        "tcp-redis-inventory-legacy-compat",
        "tcp",
        6379,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: redis database-cache on tcp/6379 during inventory"
    },
    {
        "tcp-redis-admin-plane-exposed-service",
        "tcp",
        6379,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: redis database-cache on tcp/6379 during admin-plane"
    },
    {
        "tcp-redis-admin-plane-data-store",
        "tcp",
        6379,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: redis database-cache on tcp/6379 during admin-plane"
    },
    {
        "tcp-redis-admin-plane-legacy-compat",
        "tcp",
        6379,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: redis database-cache on tcp/6379 during admin-plane"
    },
    {
        "tcp-http-alt-ingress-exposed-service",
        "tcp",
        8000,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: http-alt web on tcp/8000 during ingress"
    },
    {
        "tcp-http-alt-ingress-legacy-compat",
        "tcp",
        8000,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: http-alt web on tcp/8000 during ingress"
    },
    {
        "tcp-http-alt-egress-exposed-service",
        "tcp",
        8000,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: http-alt web on tcp/8000 during egress"
    },
    {
        "tcp-http-alt-egress-legacy-compat",
        "tcp",
        8000,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: http-alt web on tcp/8000 during egress"
    },
    {
        "tcp-http-alt-source-service-exposed-service",
        "tcp",
        8000,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: http-alt web on tcp/8000 during source-service"
    },
    {
        "tcp-http-alt-source-service-legacy-compat",
        "tcp",
        8000,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: http-alt web on tcp/8000 during source-service"
    },
    {
        "tcp-http-alt-lateral-exposed-service",
        "tcp",
        8000,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: http-alt web on tcp/8000 during lateral"
    },
    {
        "tcp-http-alt-lateral-legacy-compat",
        "tcp",
        8000,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: http-alt web on tcp/8000 during lateral"
    },
    {
        "tcp-http-alt-inventory-exposed-service",
        "tcp",
        8000,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: http-alt web on tcp/8000 during inventory"
    },
    {
        "tcp-http-alt-inventory-legacy-compat",
        "tcp",
        8000,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: http-alt web on tcp/8000 during inventory"
    },
    {
        "tcp-http-alt-admin-plane-exposed-service",
        "tcp",
        8000,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: http-alt web on tcp/8000 during admin-plane"
    },
    {
        "tcp-http-alt-admin-plane-legacy-compat",
        "tcp",
        8000,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: http-alt web on tcp/8000 during admin-plane"
    },
    {
        "tcp-proxy-http-ingress-exposed-service",
        "tcp",
        8080,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: proxy-http web-proxy on tcp/8080 during ingress"
    },
    {
        "tcp-proxy-http-ingress-legacy-compat",
        "tcp",
        8080,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: proxy-http web-proxy on tcp/8080 during ingress"
    },
    {
        "tcp-proxy-http-egress-exposed-service",
        "tcp",
        8080,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: proxy-http web-proxy on tcp/8080 during egress"
    },
    {
        "tcp-proxy-http-egress-legacy-compat",
        "tcp",
        8080,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: proxy-http web-proxy on tcp/8080 during egress"
    },
    {
        "tcp-proxy-http-source-service-exposed-service",
        "tcp",
        8080,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: proxy-http web-proxy on tcp/8080 during source-service"
    },
    {
        "tcp-proxy-http-source-service-legacy-compat",
        "tcp",
        8080,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: proxy-http web-proxy on tcp/8080 during source-service"
    },
    {
        "tcp-proxy-http-lateral-exposed-service",
        "tcp",
        8080,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: proxy-http web-proxy on tcp/8080 during lateral"
    },
    {
        "tcp-proxy-http-lateral-legacy-compat",
        "tcp",
        8080,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: proxy-http web-proxy on tcp/8080 during lateral"
    },
    {
        "tcp-proxy-http-inventory-exposed-service",
        "tcp",
        8080,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: proxy-http web-proxy on tcp/8080 during inventory"
    },
    {
        "tcp-proxy-http-inventory-legacy-compat",
        "tcp",
        8080,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: proxy-http web-proxy on tcp/8080 during inventory"
    },
    {
        "tcp-proxy-http-admin-plane-exposed-service",
        "tcp",
        8080,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: proxy-http web-proxy on tcp/8080 during admin-plane"
    },
    {
        "tcp-proxy-http-admin-plane-legacy-compat",
        "tcp",
        8080,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: proxy-http web-proxy on tcp/8080 during admin-plane"
    },
    {
        "tcp-https-alt-ingress-exposed-service",
        "tcp",
        8443,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: https-alt web-tls on tcp/8443 during ingress"
    },
    {
        "tcp-https-alt-ingress-legacy-compat",
        "tcp",
        8443,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: https-alt web-tls on tcp/8443 during ingress"
    },
    {
        "tcp-https-alt-egress-exposed-service",
        "tcp",
        8443,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: https-alt web-tls on tcp/8443 during egress"
    },
    {
        "tcp-https-alt-egress-legacy-compat",
        "tcp",
        8443,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: https-alt web-tls on tcp/8443 during egress"
    },
    {
        "tcp-https-alt-source-service-exposed-service",
        "tcp",
        8443,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: https-alt web-tls on tcp/8443 during source-service"
    },
    {
        "tcp-https-alt-source-service-legacy-compat",
        "tcp",
        8443,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: https-alt web-tls on tcp/8443 during source-service"
    },
    {
        "tcp-https-alt-lateral-exposed-service",
        "tcp",
        8443,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: https-alt web-tls on tcp/8443 during lateral"
    },
    {
        "tcp-https-alt-lateral-legacy-compat",
        "tcp",
        8443,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: https-alt web-tls on tcp/8443 during lateral"
    },
    {
        "tcp-https-alt-inventory-exposed-service",
        "tcp",
        8443,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: https-alt web-tls on tcp/8443 during inventory"
    },
    {
        "tcp-https-alt-inventory-legacy-compat",
        "tcp",
        8443,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: https-alt web-tls on tcp/8443 during inventory"
    },
    {
        "tcp-https-alt-admin-plane-exposed-service",
        "tcp",
        8443,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: https-alt web-tls on tcp/8443 during admin-plane"
    },
    {
        "tcp-https-alt-admin-plane-legacy-compat",
        "tcp",
        8443,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: https-alt web-tls on tcp/8443 during admin-plane"
    },
    {
        "tcp-elasticsearch-ingress-exposed-service",
        "tcp",
        9200,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: elasticsearch search-database on tcp/9200 during ingress"
    },
    {
        "tcp-elasticsearch-ingress-data-store",
        "tcp",
        9200,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: elasticsearch search-database on tcp/9200 during ingress"
    },
    {
        "tcp-elasticsearch-ingress-legacy-compat",
        "tcp",
        9200,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: elasticsearch search-database on tcp/9200 during ingress"
    },
    {
        "tcp-elasticsearch-egress-exposed-service",
        "tcp",
        9200,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: elasticsearch search-database on tcp/9200 during egress"
    },
    {
        "tcp-elasticsearch-egress-data-store",
        "tcp",
        9200,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: elasticsearch search-database on tcp/9200 during egress"
    },
    {
        "tcp-elasticsearch-egress-legacy-compat",
        "tcp",
        9200,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: elasticsearch search-database on tcp/9200 during egress"
    },
    {
        "tcp-elasticsearch-source-service-exposed-service",
        "tcp",
        9200,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: elasticsearch search-database on tcp/9200 during source-service"
    },
    {
        "tcp-elasticsearch-source-service-data-store",
        "tcp",
        9200,
        "src",
        "data-store",
        "high",
        "database or cache service traffic observed: elasticsearch search-database on tcp/9200 during source-service"
    },
    {
        "tcp-elasticsearch-source-service-legacy-compat",
        "tcp",
        9200,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: elasticsearch search-database on tcp/9200 during source-service"
    },
    {
        "tcp-elasticsearch-lateral-exposed-service",
        "tcp",
        9200,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: elasticsearch search-database on tcp/9200 during lateral"
    },
    {
        "tcp-elasticsearch-lateral-data-store",
        "tcp",
        9200,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: elasticsearch search-database on tcp/9200 during lateral"
    },
    {
        "tcp-elasticsearch-lateral-legacy-compat",
        "tcp",
        9200,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: elasticsearch search-database on tcp/9200 during lateral"
    },
    {
        "tcp-elasticsearch-inventory-exposed-service",
        "tcp",
        9200,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: elasticsearch search-database on tcp/9200 during inventory"
    },
    {
        "tcp-elasticsearch-inventory-data-store",
        "tcp",
        9200,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: elasticsearch search-database on tcp/9200 during inventory"
    },
    {
        "tcp-elasticsearch-inventory-legacy-compat",
        "tcp",
        9200,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: elasticsearch search-database on tcp/9200 during inventory"
    },
    {
        "tcp-elasticsearch-admin-plane-exposed-service",
        "tcp",
        9200,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: elasticsearch search-database on tcp/9200 during admin-plane"
    },
    {
        "tcp-elasticsearch-admin-plane-data-store",
        "tcp",
        9200,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: elasticsearch search-database on tcp/9200 during admin-plane"
    },
    {
        "tcp-elasticsearch-admin-plane-legacy-compat",
        "tcp",
        9200,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: elasticsearch search-database on tcp/9200 during admin-plane"
    },
    {
        "tcp-memcached-ingress-exposed-service",
        "tcp",
        11211,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: memcached database-cache on tcp/11211 during ingress"
    },
    {
        "tcp-memcached-ingress-data-store",
        "tcp",
        11211,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: memcached database-cache on tcp/11211 during ingress"
    },
    {
        "tcp-memcached-ingress-legacy-compat",
        "tcp",
        11211,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: memcached database-cache on tcp/11211 during ingress"
    },
    {
        "tcp-memcached-egress-exposed-service",
        "tcp",
        11211,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: memcached database-cache on tcp/11211 during egress"
    },
    {
        "tcp-memcached-egress-data-store",
        "tcp",
        11211,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: memcached database-cache on tcp/11211 during egress"
    },
    {
        "tcp-memcached-egress-legacy-compat",
        "tcp",
        11211,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: memcached database-cache on tcp/11211 during egress"
    },
    {
        "tcp-memcached-source-service-exposed-service",
        "tcp",
        11211,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: memcached database-cache on tcp/11211 during source-service"
    },
    {
        "tcp-memcached-source-service-data-store",
        "tcp",
        11211,
        "src",
        "data-store",
        "high",
        "database or cache service traffic observed: memcached database-cache on tcp/11211 during source-service"
    },
    {
        "tcp-memcached-source-service-legacy-compat",
        "tcp",
        11211,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: memcached database-cache on tcp/11211 during source-service"
    },
    {
        "tcp-memcached-lateral-exposed-service",
        "tcp",
        11211,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: memcached database-cache on tcp/11211 during lateral"
    },
    {
        "tcp-memcached-lateral-data-store",
        "tcp",
        11211,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: memcached database-cache on tcp/11211 during lateral"
    },
    {
        "tcp-memcached-lateral-legacy-compat",
        "tcp",
        11211,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: memcached database-cache on tcp/11211 during lateral"
    },
    {
        "tcp-memcached-inventory-exposed-service",
        "tcp",
        11211,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: memcached database-cache on tcp/11211 during inventory"
    },
    {
        "tcp-memcached-inventory-data-store",
        "tcp",
        11211,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: memcached database-cache on tcp/11211 during inventory"
    },
    {
        "tcp-memcached-inventory-legacy-compat",
        "tcp",
        11211,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: memcached database-cache on tcp/11211 during inventory"
    },
    {
        "tcp-memcached-admin-plane-exposed-service",
        "tcp",
        11211,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: memcached database-cache on tcp/11211 during admin-plane"
    },
    {
        "tcp-memcached-admin-plane-data-store",
        "tcp",
        11211,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: memcached database-cache on tcp/11211 during admin-plane"
    },
    {
        "tcp-memcached-admin-plane-legacy-compat",
        "tcp",
        11211,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: memcached database-cache on tcp/11211 during admin-plane"
    },
    {
        "tcp-mongodb-ingress-exposed-service",
        "tcp",
        27017,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: mongodb database on tcp/27017 during ingress"
    },
    {
        "tcp-mongodb-ingress-data-store",
        "tcp",
        27017,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: mongodb database on tcp/27017 during ingress"
    },
    {
        "tcp-mongodb-ingress-legacy-compat",
        "tcp",
        27017,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: mongodb database on tcp/27017 during ingress"
    },
    {
        "tcp-mongodb-egress-exposed-service",
        "tcp",
        27017,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: mongodb database on tcp/27017 during egress"
    },
    {
        "tcp-mongodb-egress-data-store",
        "tcp",
        27017,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: mongodb database on tcp/27017 during egress"
    },
    {
        "tcp-mongodb-egress-legacy-compat",
        "tcp",
        27017,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: mongodb database on tcp/27017 during egress"
    },
    {
        "tcp-mongodb-source-service-exposed-service",
        "tcp",
        27017,
        "src",
        "exposed-service",
        "medium",
        "service exposure observed: mongodb database on tcp/27017 during source-service"
    },
    {
        "tcp-mongodb-source-service-data-store",
        "tcp",
        27017,
        "src",
        "data-store",
        "high",
        "database or cache service traffic observed: mongodb database on tcp/27017 during source-service"
    },
    {
        "tcp-mongodb-source-service-legacy-compat",
        "tcp",
        27017,
        "src",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: mongodb database on tcp/27017 during source-service"
    },
    {
        "tcp-mongodb-lateral-exposed-service",
        "tcp",
        27017,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: mongodb database on tcp/27017 during lateral"
    },
    {
        "tcp-mongodb-lateral-data-store",
        "tcp",
        27017,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: mongodb database on tcp/27017 during lateral"
    },
    {
        "tcp-mongodb-lateral-legacy-compat",
        "tcp",
        27017,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: mongodb database on tcp/27017 during lateral"
    },
    {
        "tcp-mongodb-inventory-exposed-service",
        "tcp",
        27017,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: mongodb database on tcp/27017 during inventory"
    },
    {
        "tcp-mongodb-inventory-data-store",
        "tcp",
        27017,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: mongodb database on tcp/27017 during inventory"
    },
    {
        "tcp-mongodb-inventory-legacy-compat",
        "tcp",
        27017,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: mongodb database on tcp/27017 during inventory"
    },
    {
        "tcp-mongodb-admin-plane-exposed-service",
        "tcp",
        27017,
        "dst",
        "exposed-service",
        "medium",
        "service exposure observed: mongodb database on tcp/27017 during admin-plane"
    },
    {
        "tcp-mongodb-admin-plane-data-store",
        "tcp",
        27017,
        "dst",
        "data-store",
        "high",
        "database or cache service traffic observed: mongodb database on tcp/27017 during admin-plane"
    },
    {
        "tcp-mongodb-admin-plane-legacy-compat",
        "tcp",
        27017,
        "dst",
        "legacy-compat",
        "medium",
        "legacy compatibility service observed: mongodb database on tcp/27017 during admin-plane"
    },
};
std::vector<TrafficInsight> evaluate_traffic_insights(const PacketMetadata& metadata) {
    std::vector<TrafficInsight> out;
    auto proto = core::lower(metadata.protocol);
    for (const auto& rule : kTrafficHeuristics) {
        if (proto != rule.protocol) continue;
        bool port_match = false;
        if (std::string(rule.side) == "src") port_match = metadata.src_port == rule.port;
        else port_match = metadata.dst_port == rule.port;
        if (!port_match) continue;
        out.push_back(TrafficInsight{rule.id, rule.severity, rule.description});
        if (out.size() >= 12) break;
    }
    if (!metadata.domains.empty()) {
        for (const auto& d : metadata.domains) {
            auto name = core::lower(d);
            if (name.size() > 70) out.push_back({"dns-long-name", "medium", "long DNS name observed"});
            if (name.find("xn--") != std::string::npos) out.push_back({"dns-idna", "low", "internationalized DNS label observed"});
            if (name.find("login") != std::string::npos || name.find("secure") != std::string::npos) out.push_back({"dns-credential-themed", "medium", "credential-themed DNS label observed"});
        }
    }
    return out;
}
}
