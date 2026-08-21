#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <iostream>
#include <set>
#include <algorithm>

namespace dpi {

inline bool is_known_bad_port(uint16_t port) {
    static const std::set<uint16_t> bad_ports = {
        31337, 12345, 27374, 6667, 4444,
    };
    return bad_ports.count(port) > 0;
}

class PortScanDetector {
public:
    PortScanDetector(int threshold = 10, std::chrono::seconds window = std::chrono::seconds(10))
        : threshold_(threshold), window_(window) {}

    bool record_syn(const std::string& src_ip, uint16_t dst_port) {
        auto now = std::chrono::steady_clock::now();
        auto& entry = history_[src_ip];

        entry.erase(
            std::remove_if(entry.begin(), entry.end(),
                [&](const PortHit& hit) { return now - hit.timestamp > window_; }),
            entry.end());

        entry.push_back({dst_port, now});

        std::set<uint16_t> distinct_ports;
        for (const auto& hit : entry) distinct_ports.insert(hit.port);

        if (distinct_ports.size() >= static_cast<size_t>(threshold_) && !already_flagged_.count(src_ip)) {
            already_flagged_.insert(src_ip);
            return true;
        }
        return false;
    }

private:
    struct PortHit {
        uint16_t port;
        std::chrono::steady_clock::time_point timestamp;
    };
    int threshold_;
    std::chrono::seconds window_;
    std::unordered_map<std::string, std::vector<PortHit>> history_;
    std::set<std::string> already_flagged_;
};

inline std::string check_malformed_ip(int ip_header_len, size_t captured_len, size_t eth_header_len) {
    if (ip_header_len < 20) {
        return "IP header length claims " + std::to_string(ip_header_len) +
               " bytes, minimum valid is 20";
    }
    if (ip_header_len > 60) {
        return "IP header length " + std::to_string(ip_header_len) +
               " exceeds protocol maximum of 60 bytes";
    }
    return "";
}

inline void print_alert(const std::string& message) {
    std::cout << "  \033[1;31m[ALERT]\033[0m " << message << "\n";
}

} // namespace dpi
