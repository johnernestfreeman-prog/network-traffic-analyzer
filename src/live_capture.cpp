// Phase 2: Network Traffic Analyzer — live capture
// Lists available network interfaces, lets the user pick one, and captures
// packets live off the real NIC (via Npcap on Windows / libpcap on Linux),
// decoding them with the same shared parser as the Phase 1 file reader.
//
// NOTE (Windows): capturing live traffic requires Administrator privileges.
// Run this from an elevated (Run as Administrator) terminal, or capture
// will fail to open the device even though it lists correctly.
//
// NOTE (Linux/WSL2): requires root (sudo), and WSL2's virtual network
// adapter only sees WSL2's own traffic, not the Windows host's real NICs.

#include "../include/packet_parser.h"
#include <iostream>
#include <vector>
#include <string>

void packet_handler(u_char* user_data, const struct pcap_pkthdr* header, const u_char* packet) {
    pktparse::handle_packet(header, packet);
}

int main(int argc, char* argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // --- Step 1: enumerate available interfaces ---
    pcap_if_t* all_devices;
    if (pcap_findalldevs(&all_devices, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << "\n";
        return 1;
    }

    std::vector<pcap_if_t*> device_list;
    int i = 0;
    std::cout << "Available network interfaces:\n";
    for (pcap_if_t* d = all_devices; d != nullptr; d = d->next) {
        device_list.push_back(d);
        std::cout << "  [" << i << "] " << d->name;
        if (d->description) {
            std::cout << "  (" << d->description << ")";
        }
        std::cout << "\n";
        i++;
    }

    if (device_list.empty()) {
        std::cerr << "No interfaces found. On Windows, make sure Npcap is installed "
                     "and you're running this terminal as Administrator.\n";
        return 1;
    }

    // --- Step 2: let the user pick one ---
    std::cout << "\nSelect an interface by number: ";
    int choice;
    std::cin >> choice;
    if (choice < 0 || choice >= static_cast<int>(device_list.size())) {
        std::cerr << "Invalid selection.\n";
        pcap_freealldevs(all_devices);
        return 1;
    }
    pcap_if_t* selected = device_list[choice];

    // --- Step 3: open the interface for live capture ---
    // Parameters: device name, snapshot length (max bytes per packet),
    // promiscuous mode (0 = off, capture only traffic to/from this host),
    // read timeout in ms, error buffer.
    pcap_t* handle = pcap_open_live(selected->name, 65536, 0, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Failed to open interface for capture: " << errbuf << "\n";
        std::cerr << "(On Windows, try running this terminal as Administrator.)\n";
        pcap_freealldevs(all_devices);
        return 1;
    }

    std::cout << "\nCapturing live on: " << selected->name
              << "\nPress Ctrl+C to stop.\n";

    pcap_freealldevs(all_devices);

    int result = pcap_loop(handle, 0, packet_handler, nullptr);
    if (result == -1) {
        std::cerr << "Error during capture: " << pcap_geterr(handle) << "\n";
    }

    pcap_close(handle);
    return 0;
}
