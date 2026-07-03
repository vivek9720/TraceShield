#pragma once
#include "packet/packet.hpp"
#include <string>
#include <vector>

namespace traceshield::packet {
struct TrafficInsight {
    std::string id;
    std::string severity;
    std::string description;
};
std::vector<TrafficInsight> evaluate_traffic_insights(const PacketMetadata& metadata);
}
