#include "../include/packet_parser.h"
#include <iostream>

void packet_handler(u_char* user_data, const struct pcap_pkthdr* header, const u_char* packet) {
    pktparse::handle_packet(header, packet);
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
