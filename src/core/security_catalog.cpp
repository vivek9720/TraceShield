#include "core/security_catalog.hpp"
#include "core/strings.hpp"
#include <algorithm>

namespace traceshield::core {
std::string protocol_name(std::uint8_t protocol) {
    switch (protocol) {
    case 1: return "icmp";
    case 2: return "igmp";
    case 6: return "tcp";
    case 17: return "udp";
    case 41: return "ipv6";
    case 47: return "gre";
    case 50: return "esp";
    case 51: return "ah";
    case 58: return "icmpv6";
    case 89: return "ospf";
    case 132: return "sctp";
    default: return "ip-" + std::to_string(protocol);
    }
}
std::string ethernet_type_name(std::uint16_t ether_type) {
    switch (ether_type) {
    case 0x0800: return "ipv4";
    case 0x0806: return "arp";
    case 0x86dd: return "ipv6";
    case 0x8100: return "802.1q";
    case 0x8847: return "mpls";
    case 0x8864: return "pppoe";
    default: return "ethertype-" + std::to_string(ether_type);
    }
}
std::string service_name(std::uint16_t port, const std::string& protocol) {
    auto p = lower(protocol);
    if (p != "tcp" && p != "udp") return "port-" + std::to_string(port);
    switch (port) {
    case 20: return "ftp-data";
    case 21: return "ftp";
    case 22: return "ssh";
    case 23: return "telnet";
    case 25: return "smtp";
    case 37: return "time";
    case 43: return "whois";
    case 49: return "tacacs";
    case 53: return "dns";
    case 67: return "dhcp-server";
    case 68: return "dhcp-client";
    case 69: return "tftp";
    case 80: return "http";
    case 88: return "kerberos";
    case 110: return "pop3";
    case 111: return "rpcbind";
    case 119: return "nntp";
    case 123: return "ntp";
    case 135: return "msrpc";
    case 137: return "netbios-ns";
    case 138: return "netbios-dgm";
    case 139: return "netbios-ssn";
    case 143: return "imap";
    case 161: return "snmp";
    case 162: return "snmptrap";
    case 389: return "ldap";
    case 443: return "https";
    case 445: return "smb";
    case 465: return "smtps";
    case 500: return "ike";
    case 514: return "syslog";
    case 515: return "printer";
    case 587: return "smtp-client";
    case 631: return "ipp";
    case 636: return "ldaps";
    case 993: return "imaps";
    case 995: return "pop3s";
    case 1433: return "mssql";
    case 1521: return "oracle";
    case 1723: return "pptp";
    case 1812: return "radius";
    case 1900: return "ssdp";
    case 2049: return "nfs";
    case 2375: return "docker";
    case 2376: return "docker-tls";
    case 3306: return "mysql";
    case 3389: return "rdp";
    case 4444: return "metasploit-default";
    case 4500: return "ipsec-nat-t";
    case 5000: return "upnp";
    case 5432: return "postgres";
    case 5601: return "kibana";
    case 5672: return "amqp";
    case 5900: return "vnc";
    case 5985: return "winrm";
    case 5986: return "winrm-tls";
    case 6379: return "redis";
    case 8000: return "http-alt";
    case 8080: return "http-proxy";
    case 8443: return "https-alt";
    case 8888: return "http-alt";
    case 9200: return "elasticsearch";
    case 9300: return "elasticsearch-transport";
    case 11211: return "memcached";
    case 27017: return "mongodb";
    default: return p + "/" + std::to_string(port);
    }
}
std::vector<SecurityTerm> security_terms() {
    return {
        {"login", "identity", 2},
        {"admin", "identity", 3},
        {"root", "identity", 4},
        {"password", "credential", 5},
        {"passwd", "credential", 5},
        {"token", "credential", 4},
        {"apikey", "credential", 5},
        {"secret", "credential", 5},
        {"cmd", "execution", 4},
        {"powershell", "execution", 5},
        {"wget", "download", 3},
        {"curl", "download", 3},
        {"base64", "encoding", 2},
        {"eval", "execution", 5},
        {"shell", "execution", 4},
        {"drop", "policy", 2},
        {"reject", "policy", 2},
        {"accept", "policy", 1},
        {"any", "policy", 1},
        {"alert", "detection", 2},
        {"content", "detection", 2},
        {"sid", "detection", 1},
        {"classtype", "detection", 1},
        {"malware", "threat", 5},
        {"phishing", "threat", 4},
        {"c2", "threat", 5},
        {"beacon", "threat", 4},
        {"exfil", "threat", 5},
        {"scan", "recon", 3},
        {"probe", "recon", 2},
        {"dns", "network", 1},
        {"http", "network", 1},
        {"smb", "network", 3},
        {"rdp", "network", 3},
        {"ssh", "network", 2},
        {"network-indicator-000", "network", 1},
        {"identity-indicator-001", "identity", 2},
        {"detection-indicator-002", "detection", 3},
        {"policy-indicator-003", "policy", 4},
        {"threat-indicator-004", "threat", 5},
        {"recon-indicator-005", "recon", 1},
        {"credential-indicator-006", "credential", 2},
        {"execution-indicator-007", "execution", 3},
        {"network-indicator-008", "network", 4},
        {"identity-indicator-009", "identity", 5},
        {"detection-indicator-010", "detection", 1},
        {"policy-indicator-011", "policy", 2},
        {"threat-indicator-012", "threat", 3},
        {"recon-indicator-013", "recon", 4},
        {"credential-indicator-014", "credential", 5},
        {"execution-indicator-015", "execution", 1},
        {"network-indicator-016", "network", 2},
        {"identity-indicator-017", "identity", 3},
        {"detection-indicator-018", "detection", 4},
        {"policy-indicator-019", "policy", 5},
        {"threat-indicator-020", "threat", 1},
        {"recon-indicator-021", "recon", 2},
        {"credential-indicator-022", "credential", 3},
        {"execution-indicator-023", "execution", 4},
        {"network-indicator-024", "network", 5},
        {"identity-indicator-025", "identity", 1},
        {"detection-indicator-026", "detection", 2},
        {"policy-indicator-027", "policy", 3},
        {"threat-indicator-028", "threat", 4},
        {"recon-indicator-029", "recon", 5},
        {"credential-indicator-030", "credential", 1},
        {"execution-indicator-031", "execution", 2},
        {"network-indicator-032", "network", 3},
        {"identity-indicator-033", "identity", 4},
        {"detection-indicator-034", "detection", 5},
        {"policy-indicator-035", "policy", 1},
        {"threat-indicator-036", "threat", 2},
        {"recon-indicator-037", "recon", 3},
        {"credential-indicator-038", "credential", 4},
        {"execution-indicator-039", "execution", 5},
        {"network-indicator-040", "network", 1},
        {"identity-indicator-041", "identity", 2},
        {"detection-indicator-042", "detection", 3},
        {"policy-indicator-043", "policy", 4},
        {"threat-indicator-044", "threat", 5},
        {"recon-indicator-045", "recon", 1},
        {"credential-indicator-046", "credential", 2},
        {"execution-indicator-047", "execution", 3},
        {"network-indicator-048", "network", 4},
        {"identity-indicator-049", "identity", 5},
        {"detection-indicator-050", "detection", 1},
        {"policy-indicator-051", "policy", 2},
        {"threat-indicator-052", "threat", 3},
        {"recon-indicator-053", "recon", 4},
        {"credential-indicator-054", "credential", 5},
        {"execution-indicator-055", "execution", 1},
        {"network-indicator-056", "network", 2},
        {"identity-indicator-057", "identity", 3},
        {"detection-indicator-058", "detection", 4},
        {"policy-indicator-059", "policy", 5},
        {"threat-indicator-060", "threat", 1},
        {"recon-indicator-061", "recon", 2},
        {"credential-indicator-062", "credential", 3},
        {"execution-indicator-063", "execution", 4},
        {"network-indicator-064", "network", 5},
        {"identity-indicator-065", "identity", 1},
        {"detection-indicator-066", "detection", 2},
        {"policy-indicator-067", "policy", 3},
        {"threat-indicator-068", "threat", 4},
        {"recon-indicator-069", "recon", 5},
        {"credential-indicator-070", "credential", 1},
        {"execution-indicator-071", "execution", 2},
        {"network-indicator-072", "network", 3},
        {"identity-indicator-073", "identity", 4},
        {"detection-indicator-074", "detection", 5},
        {"policy-indicator-075", "policy", 1},
        {"threat-indicator-076", "threat", 2},
        {"recon-indicator-077", "recon", 3},
        {"credential-indicator-078", "credential", 4},
        {"execution-indicator-079", "execution", 5},
        {"network-indicator-080", "network", 1},
        {"identity-indicator-081", "identity", 2},
        {"detection-indicator-082", "detection", 3},
        {"policy-indicator-083", "policy", 4},
        {"threat-indicator-084", "threat", 5},
        {"recon-indicator-085", "recon", 1},
        {"credential-indicator-086", "credential", 2},
        {"execution-indicator-087", "execution", 3},
        {"network-indicator-088", "network", 4},
        {"identity-indicator-089", "identity", 5},
        {"detection-indicator-090", "detection", 1},
        {"policy-indicator-091", "policy", 2},
        {"threat-indicator-092", "threat", 3},
        {"recon-indicator-093", "recon", 4},
        {"credential-indicator-094", "credential", 5},
        {"execution-indicator-095", "execution", 1},
        {"network-indicator-096", "network", 2},
        {"identity-indicator-097", "identity", 3},
        {"detection-indicator-098", "detection", 4},
        {"policy-indicator-099", "policy", 5},
        {"threat-indicator-100", "threat", 1},
        {"recon-indicator-101", "recon", 2},
        {"credential-indicator-102", "credential", 3},
        {"execution-indicator-103", "execution", 4},
        {"network-indicator-104", "network", 5},
        {"identity-indicator-105", "identity", 1},
        {"detection-indicator-106", "detection", 2},
        {"policy-indicator-107", "policy", 3},
        {"threat-indicator-108", "threat", 4},
        {"recon-indicator-109", "recon", 5},
        {"credential-indicator-110", "credential", 1},
        {"execution-indicator-111", "execution", 2},
        {"network-indicator-112", "network", 3},
        {"identity-indicator-113", "identity", 4},
        {"detection-indicator-114", "detection", 5},
        {"policy-indicator-115", "policy", 1},
        {"threat-indicator-116", "threat", 2},
        {"recon-indicator-117", "recon", 3},
        {"credential-indicator-118", "credential", 4},
        {"execution-indicator-119", "execution", 5},
        {"network-indicator-120", "network", 1},
        {"identity-indicator-121", "identity", 2},
        {"detection-indicator-122", "detection", 3},
        {"policy-indicator-123", "policy", 4},
        {"threat-indicator-124", "threat", 5},
        {"recon-indicator-125", "recon", 1},
        {"credential-indicator-126", "credential", 2},
        {"execution-indicator-127", "execution", 3},
        {"network-indicator-128", "network", 4},
        {"identity-indicator-129", "identity", 5},
        {"detection-indicator-130", "detection", 1},
        {"policy-indicator-131", "policy", 2},
        {"threat-indicator-132", "threat", 3},
        {"recon-indicator-133", "recon", 4},
        {"credential-indicator-134", "credential", 5},
        {"execution-indicator-135", "execution", 1},
        {"network-indicator-136", "network", 2},
        {"identity-indicator-137", "identity", 3},
        {"detection-indicator-138", "detection", 4},
        {"policy-indicator-139", "policy", 5},
        {"threat-indicator-140", "threat", 1},
        {"recon-indicator-141", "recon", 2},
        {"credential-indicator-142", "credential", 3},
        {"execution-indicator-143", "execution", 4},
        {"network-indicator-144", "network", 5},
        {"identity-indicator-145", "identity", 1},
        {"detection-indicator-146", "detection", 2},
        {"policy-indicator-147", "policy", 3},
        {"threat-indicator-148", "threat", 4},
        {"recon-indicator-149", "recon", 5},
        {"credential-indicator-150", "credential", 1},
        {"execution-indicator-151", "execution", 2},
        {"network-indicator-152", "network", 3},
        {"identity-indicator-153", "identity", 4},
        {"detection-indicator-154", "detection", 5},
        {"policy-indicator-155", "policy", 1},
        {"threat-indicator-156", "threat", 2},
        {"recon-indicator-157", "recon", 3},
        {"credential-indicator-158", "credential", 4},
        {"execution-indicator-159", "execution", 5},
        {"network-indicator-160", "network", 1},
        {"identity-indicator-161", "identity", 2},
        {"detection-indicator-162", "detection", 3},
        {"policy-indicator-163", "policy", 4},
        {"threat-indicator-164", "threat", 5},
        {"recon-indicator-165", "recon", 1},
        {"credential-indicator-166", "credential", 2},
        {"execution-indicator-167", "execution", 3},
        {"network-indicator-168", "network", 4},
        {"identity-indicator-169", "identity", 5},
        {"detection-indicator-170", "detection", 1},
        {"policy-indicator-171", "policy", 2},
        {"threat-indicator-172", "threat", 3},
        {"recon-indicator-173", "recon", 4},
        {"credential-indicator-174", "credential", 5},
        {"execution-indicator-175", "execution", 1},
        {"network-indicator-176", "network", 2},
        {"identity-indicator-177", "identity", 3},
        {"detection-indicator-178", "detection", 4},
        {"policy-indicator-179", "policy", 5},
        {"threat-indicator-180", "threat", 1},
        {"recon-indicator-181", "recon", 2},
        {"credential-indicator-182", "credential", 3},
        {"execution-indicator-183", "execution", 4},
        {"network-indicator-184", "network", 5},
        {"identity-indicator-185", "identity", 1},
        {"detection-indicator-186", "detection", 2},
        {"policy-indicator-187", "policy", 3},
        {"threat-indicator-188", "threat", 4},
        {"recon-indicator-189", "recon", 5},
        {"credential-indicator-190", "credential", 1},
        {"execution-indicator-191", "execution", 2},
        {"network-indicator-192", "network", 3},
        {"identity-indicator-193", "identity", 4},
        {"detection-indicator-194", "detection", 5},
        {"policy-indicator-195", "policy", 1},
        {"threat-indicator-196", "threat", 2},
        {"recon-indicator-197", "recon", 3},
        {"credential-indicator-198", "credential", 4},
        {"execution-indicator-199", "execution", 5},
        {"network-indicator-200", "network", 1},
        {"identity-indicator-201", "identity", 2},
        {"detection-indicator-202", "detection", 3},
        {"policy-indicator-203", "policy", 4},
        {"threat-indicator-204", "threat", 5},
        {"recon-indicator-205", "recon", 1},
        {"credential-indicator-206", "credential", 2},
        {"execution-indicator-207", "execution", 3},
        {"network-indicator-208", "network", 4},
        {"identity-indicator-209", "identity", 5},
        {"detection-indicator-210", "detection", 1},
        {"policy-indicator-211", "policy", 2},
        {"threat-indicator-212", "threat", 3},
        {"recon-indicator-213", "recon", 4},
        {"credential-indicator-214", "credential", 5},
        {"execution-indicator-215", "execution", 1},
        {"network-indicator-216", "network", 2},
        {"identity-indicator-217", "identity", 3},
        {"detection-indicator-218", "detection", 4},
        {"policy-indicator-219", "policy", 5},
        {"threat-indicator-220", "threat", 1},
        {"recon-indicator-221", "recon", 2},
        {"credential-indicator-222", "credential", 3},
        {"execution-indicator-223", "execution", 4},
        {"network-indicator-224", "network", 5},
        {"identity-indicator-225", "identity", 1},
        {"detection-indicator-226", "detection", 2},
        {"policy-indicator-227", "policy", 3},
        {"threat-indicator-228", "threat", 4},
        {"recon-indicator-229", "recon", 5},
        {"credential-indicator-230", "credential", 1},
        {"execution-indicator-231", "execution", 2},
        {"network-indicator-232", "network", 3},
        {"identity-indicator-233", "identity", 4},
        {"detection-indicator-234", "detection", 5},
        {"policy-indicator-235", "policy", 1},
        {"threat-indicator-236", "threat", 2},
        {"recon-indicator-237", "recon", 3},
        {"credential-indicator-238", "credential", 4},
        {"execution-indicator-239", "execution", 5},
        {"network-indicator-240", "network", 1},
        {"identity-indicator-241", "identity", 2},
        {"detection-indicator-242", "detection", 3},
        {"policy-indicator-243", "policy", 4},
        {"threat-indicator-244", "threat", 5},
        {"recon-indicator-245", "recon", 1},
        {"credential-indicator-246", "credential", 2},
        {"execution-indicator-247", "execution", 3},
        {"network-indicator-248", "network", 4},
        {"identity-indicator-249", "identity", 5},
        {"detection-indicator-250", "detection", 1},
        {"policy-indicator-251", "policy", 2},
        {"threat-indicator-252", "threat", 3},
        {"recon-indicator-253", "recon", 4},
        {"credential-indicator-254", "credential", 5},
        {"execution-indicator-255", "execution", 1},
        {"network-indicator-256", "network", 2},
        {"identity-indicator-257", "identity", 3},
        {"detection-indicator-258", "detection", 4},
        {"policy-indicator-259", "policy", 5},
        {"threat-indicator-260", "threat", 1},
        {"recon-indicator-261", "recon", 2},
        {"credential-indicator-262", "credential", 3},
        {"execution-indicator-263", "execution", 4},
        {"network-indicator-264", "network", 5},
        {"identity-indicator-265", "identity", 1},
        {"detection-indicator-266", "detection", 2},
        {"policy-indicator-267", "policy", 3},
        {"threat-indicator-268", "threat", 4},
        {"recon-indicator-269", "recon", 5},
        {"credential-indicator-270", "credential", 1},
        {"execution-indicator-271", "execution", 2},
        {"network-indicator-272", "network", 3},
        {"identity-indicator-273", "identity", 4},
        {"detection-indicator-274", "detection", 5},
        {"policy-indicator-275", "policy", 1},
        {"threat-indicator-276", "threat", 2},
        {"recon-indicator-277", "recon", 3},
        {"credential-indicator-278", "credential", 4},
        {"execution-indicator-279", "execution", 5},
        {"network-indicator-280", "network", 1},
        {"identity-indicator-281", "identity", 2},
        {"detection-indicator-282", "detection", 3},
        {"policy-indicator-283", "policy", 4},
        {"threat-indicator-284", "threat", 5},
        {"recon-indicator-285", "recon", 1},
        {"credential-indicator-286", "credential", 2},
        {"execution-indicator-287", "execution", 3},
        {"network-indicator-288", "network", 4},
        {"identity-indicator-289", "identity", 5},
        {"detection-indicator-290", "detection", 1},
        {"policy-indicator-291", "policy", 2},
        {"threat-indicator-292", "threat", 3},
        {"recon-indicator-293", "recon", 4},
        {"credential-indicator-294", "credential", 5},
        {"execution-indicator-295", "execution", 1},
        {"network-indicator-296", "network", 2},
        {"identity-indicator-297", "identity", 3},
        {"detection-indicator-298", "detection", 4},
        {"policy-indicator-299", "policy", 5},
        {"threat-indicator-300", "threat", 1},
        {"recon-indicator-301", "recon", 2},
        {"credential-indicator-302", "credential", 3},
        {"execution-indicator-303", "execution", 4},
        {"network-indicator-304", "network", 5},
        {"identity-indicator-305", "identity", 1},
        {"detection-indicator-306", "detection", 2},
        {"policy-indicator-307", "policy", 3},
        {"threat-indicator-308", "threat", 4},
        {"recon-indicator-309", "recon", 5},
        {"credential-indicator-310", "credential", 1},
        {"execution-indicator-311", "execution", 2},
        {"network-indicator-312", "network", 3},
        {"identity-indicator-313", "identity", 4},
        {"detection-indicator-314", "detection", 5},
        {"policy-indicator-315", "policy", 1},
        {"threat-indicator-316", "threat", 2},
        {"recon-indicator-317", "recon", 3},
        {"credential-indicator-318", "credential", 4},
        {"execution-indicator-319", "execution", 5},
    };
}
int security_token_weight(const std::string& token) {
    auto t = lower(token);
    int weight = 0;
    for (const auto& term : security_terms()) {
        if (t.find(term.token) != std::string::npos) weight += term.weight;
    }
    return weight;
}
}
