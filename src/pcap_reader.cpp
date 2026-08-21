// Phase 1: Network Traffic Analyzer
// Reads a .pcap file and parses Ethernet / IPv4 / TCP-UDP headers by hand.
//
// Why parse headers manually instead of leaning on a library from day one?
// Interviewers ask "how does a TCP header actually look on the wire" — this
// program is the answer. Phase 2 swaps in pcap++ for live capture ergonomics,
// but the header-parsing knowledge carries forward either way.
//
// Portability note: this file defines its own packet header parsing instead
// of including OS networking headers (netinet/*.h on Linux, winsock2.h on
// Windows have different, incompatible struct layouts and don't exist on
// both platforms). Hand-parsing bytes means the exact same code compiles
// unchanged on Linux, Windows, and macOS — no #ifdef maze in the logic.

#include <pcap.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>
#include <iostream>

// --- Byte-order helpers -----------------------------------------------
// Network byte order is big-endian. x86/x64 CPUs are little-endian, so
// multi-byte fields (ports, lengths) need swapping when read out of a
// captured packet. Writing these by hand avoids depending on
// platform-specific ntohs()/ntohl() headers entirely.
uint16_t read_be16(const uint8_t* p) {
    return (static_cast<uint16_t>(p[0]) << 8) | p[1];
}

// --- Header sizes (fixed, in bytes) ------------------------------------
constexpr size_t ETHERNET_HEADER_LEN = 14; // 6 dst MAC + 6 src MAC + 2 EtherType
constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
constexpr uint8_t IP_PROTO_TCP = 6;
constexpr uint8_t IP_PROTO_UDP = 17;

void print_mac(const uint8_t* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Called by pcap_loop() once per packet in the file.
void packet_handler(u_char* user_data, const struct pcap_pkthdr* header, const u_char* packet) {
    static int packet_count = 0;
    packet_count++;

    std::cout << "\n--- Packet #" << packet_count
              << "  (" << header->len << " bytes on wire, "
              << header->caplen << " bytes captured) ---\n";

    // --- Ethernet header ---
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

    // --- IPv4 header (variable length, min 20 bytes) ---
    const uint8_t* ip_start = packet + ETHERNET_HEADER_LEN;
    if (header->caplen < ETHERNET_HEADER_LEN + 20) {
        std::cout << "  [truncated before IP header]\n";
        return;
    }

    uint8_t version_ihl = ip_start[0];
    int ip_header_len = (version_ihl & 0x0F) * 4; // low nibble = header length in 32-bit words
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

    // --- Transport layer ---
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

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <path-to-pcap-file>\n";
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(argv[1], errbuf);
    if (handle == nullptr) {
        std::cerr << "Failed to open pcap file: " << errbuf << "\n";
        return 1;
    }

    std::cout << "Reading packets from: " << argv[1] << "\n";

    int result = pcap_loop(handle, 0, packet_handler, nullptr);
    if (result == -1) {
        std::cerr << "Error reading packets: " << pcap_geterr(handle) << "\n";
    }

    pcap_close(handle);
    return 0;
}
