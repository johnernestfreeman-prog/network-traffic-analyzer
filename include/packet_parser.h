#pragma once

#include <pcap.h>
#include <cstdio>
#include <cstdint>
#include <iostream>

namespace pktparse {

inline uint16_t read_be16(const uint8_t* p) {
    return (static_cast<uint16_t>(p[0]) << 8) | p[1];
}

constexpr size_t ETHERNET_HEADER_LEN = 14;
constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
constexpr uint8_t IP_PROTO_TCP = 6;
constexpr uint8_t IP_PROTO_UDP = 17;

inline void print_mac(const uint8_t* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

inline void handle_packet(const struct pcap_pkthdr* header, const u_char* packet) {
    static int packet_count = 0;
    packet_count++;

    std::cout << "\n--- Packet #" << packet_count
              << "  (" << header->len << " bytes on wire, "
              << header->caplen << " bytes captured) ---\n";

    if (header->caplen < ETHERNET_HEADER_LEN) {
        std::cout << "  [truncated before Ethernet header]\n";
        return;
    }
    const uint8_t* dst_mac = packet;
    const uint8_t* src_mac = packet + 6;
    uint16_t eth_type = read_be16(packet + 12);

    std::cout << "  Ethernet: src=";
    print_mac(src_mac);
    std::cout << "  dst=";
    print_mac(dst_mac);
    std::cout << "\n";

    if (eth_type != ETHERTYPE_IPV4) {
        std::cout << "  [non-IPv4 EtherType 0x" << std::hex << eth_type << std::dec << ", skipping]\n";
        return;
    }

    const uint8_t* ip_start = packet + ETHERNET_HEADER_LEN;
    if (header->caplen < ETHERNET_HEADER_LEN + 20) {
        std::cout << "  [truncated before IP header]\n";
        return;
    }

    uint8_t version_ihl = ip_start[0];
    int ip_header_len = (version_ihl & 0x0F) * 4;
    uint8_t ttl = ip_start[8];
    uint8_t protocol = ip_start[9];
    const uint8_t* src_ip_bytes = ip_start + 12;
    const uint8_t* dst_ip_bytes = ip_start + 16;

    char src_ip[16], dst_ip[16];
    snprintf(src_ip, sizeof(src_ip), "%d.%d.%d.%d",
             src_ip_bytes[0], src_ip_bytes[1], src_ip_bytes[2], src_ip_bytes[3]);
    snprintf(dst_ip, sizeof(dst_ip), "%d.%d.%d.%d",
             dst_ip_bytes[0], dst_ip_bytes[1], dst_ip_bytes[2], dst_ip_bytes[3]);

    std::cout << "  IPv4: " << src_ip << " -> " << dst_ip
              << "  (header=" << ip_header_len << "B, ttl=" << (int)ttl
              << ", proto=" << (int)protocol << ")\n";

    const uint8_t* transport_start = ip_start + ip_header_len;
    size_t bytes_so_far = ETHERNET_HEADER_LEN + ip_header_len;

    if (protocol == IP_PROTO_TCP) {
        if (header->caplen < bytes_so_far + 20) {
            std::cout << "  [truncated before TCP header]\n";
            return;
        }
        uint16_t src_port = read_be16(transport_start);
        uint16_t dst_port = read_be16(transport_start + 2);
        uint8_t flags = transport_start[13];

        std::cout << "  TCP: srcport=" << src_port << " -> dstport=" << dst_port << "  flags=[";
        if (flags & 0x02) std::cout << "SYN ";
        if (flags & 0x10) std::cout << "ACK ";
        if (flags & 0x01) std::cout << "FIN ";
        if (flags & 0x04) std::cout << "RST ";
        if (flags & 0x08) std::cout << "PSH ";
        std::cout << "]\n";
    } else if (protocol == IP_PROTO_UDP) {
        if (header->caplen < bytes_so_far + 8) {
            std::cout << "  [truncated before UDP header]\n";
            return;
        }
        uint16_t src_port = read_be16(transport_start);
        uint16_t dst_port = read_be16(transport_start + 2);
        uint16_t length = read_be16(transport_start + 4);

        std::cout << "  UDP: srcport=" << src_port << " -> dstport=" << dst_port
                  << "  length=" << length << "\n";
    } else {
        std::cout << "  [transport protocol " << (int)protocol << " not decoded yet]\n";
    }
}

} // namespace pktparse
