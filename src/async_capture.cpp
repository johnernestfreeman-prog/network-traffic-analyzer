#include "../include/packet_parser.h"
#include <boost/asio.hpp>
#include <iostream>
#include <vector>
#include <chrono>

using boost::asio::steady_timer;

class AsyncCapture {
public:
    AsyncCapture(boost::asio::io_context& io_context, pcap_t* handle)
        : io_context_(io_context), handle_(handle), timer_(io_context) {
        char errbuf[PCAP_ERRBUF_SIZE];
        if (pcap_setnonblock(handle_, 1, errbuf) == -1) {
            std::cerr << "Failed to set non-blocking mode: " << errbuf << "\n";
        }
        schedule_poll();
    }

    int packets_processed() const { return total_packets_; }

private:
    void schedule_poll() {
        timer_.expires_after(std::chrono::milliseconds(50));
        timer_.async_wait([this](const boost::system::error_code& ec) {
            if (ec) return;
            poll_once();
            schedule_poll();
        });
    }

    void poll_once() {
        int result = pcap_dispatch(handle_, 50,
            [](u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
                auto* self = reinterpret_cast<AsyncCapture*>(user);
                pktparse::handle_packet(header, packet);
                self->total_packets_++;
            },
            reinterpret_cast<u_char*>(this));

        if (result == -1) {
            std::cerr << "Capture error: " << pcap_geterr(handle_) << "\n";
        }
    }

    boost::asio::io_context& io_context_;
    pcap_t* handle_;
    steady_timer timer_;
    int total_packets_ = 0;
};

int main(int argc, char* argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];

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
        if (d->description) std::cout << "  (" << d->description << ")";
        std::cout << "\n";
        i++;
    }

    if (device_list.empty()) {
        std::cerr << "No interfaces found.\n";
        return 1;
    }

    std::cout << "\nSelect an interface by number: ";
    int choice;
    std::cin >> choice;
    if (choice < 0 || choice >= static_cast<int>(device_list.size())) {
        std::cerr << "Invalid selection.\n";
        pcap_freealldevs(all_devices);
        return 1;
    }
    pcap_if_t* selected = device_list[choice];

    pcap_t* handle = pcap_open_live(selected->name, 65536, 0, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Failed to open interface: " << errbuf << "\n";
        pcap_freealldevs(all_devices);
        return 1;
    }
    pcap_freealldevs(all_devices);

    std::cout << "\nCapturing (async, via Boost Asio) on: " << selected->name
              << "\nThis will run for 30 seconds, then stop automatically.\n";

    boost::asio::io_context io_context;
    AsyncCapture capture(io_context, handle);

    steady_timer heartbeat(io_context);
    int seconds_elapsed = 0;
    std::function<void()> tick;
    tick = [&]() {
        heartbeat.expires_after(std::chrono::seconds(5));
        heartbeat.async_wait([&](const boost::system::error_code& ec) {
            if (ec) return;
            seconds_elapsed += 5;
            std::cout << "\n[heartbeat] " << seconds_elapsed << "s elapsed, "
                      << capture.packets_processed() << " packets so far\n";
            if (seconds_elapsed < 30) {
                tick();
            } else {
                io_context.stop();
            }
        });
    };
    tick();

    io_context.run();

    pcap_close(handle);
    std::cout << "\nCapture stopped. Total packets: " << capture.packets_processed() << "\n";
    return 0;
}
