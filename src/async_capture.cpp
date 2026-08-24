#include "../include/packet_parser.h"
#include "../include/grpc_client.h"
#include <boost/asio.hpp>
#include <iostream>
#include <vector>
#include <chrono>
#include <cstring>

using boost::asio::steady_timer;

class AsyncCapture {
public:
    AsyncCapture(boost::asio::io_context& io_context, pcap_t* handle, TrafficGrpcClient* grpc_client)
        : io_context_(io_context), handle_(handle), timer_(io_context), grpc_client_(grpc_client) {
        char errbuf[PCAP_ERRBUF_SIZE];
        if (pcap_file(handle_) == nullptr && pcap_setnonblock(handle_, 1, errbuf) == -1) {
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
                self->total_packets_++;

                pktparse::PacketCallback callback = nullptr;
                if (self->grpc_client_) {
                    callback = [self](const pktparse::PacketFields& fields) {
                        self->grpc_client_->send_packet(
                            fields.src_ip, fields.dst_ip, fields.src_port, fields.dst_port,
                            fields.protocol, fields.length_bytes, fields.tcp_flags, fields.alerts);
                    };
                }
                pktparse::handle_packet(header, packet, callback);
            },
            reinterpret_cast<u_char*>(this));

        if (result == -1) {
            std::cerr << "Capture error: " << pcap_geterr(handle_) << "\n";
        }
    }

    boost::asio::io_context& io_context_;
    pcap_t* handle_;
    steady_timer timer_;
    TrafficGrpcClient* grpc_client_;
    int total_packets_ = 0;
};

int main(int argc, char* argv[]) {
    bool use_grpc = false;
    std::string file_path;
    for (int a = 1; a < argc; a++) {
        if (std::strcmp(argv[a], "--grpc") == 0) use_grpc = true;
        else if (std::strcmp(argv[a], "--file") == 0 && a + 1 < argc) { file_path = argv[++a]; }
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = nullptr;
    std::string interface_name;

    if (!file_path.empty()) {
        handle = pcap_open_offline(file_path.c_str(), errbuf);
        if (handle == nullptr) {
            std::cerr << "Failed to open pcap file: " << errbuf << "\n";
            return 1;
        }
        interface_name = "file:" + file_path;
        std::cout << "Reading from pcap file: " << file_path << "\n";
    } else {
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
    interface_name = selected->name;

    handle = pcap_open_live(selected->name, 65536, 0, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Failed to open interface: " << errbuf << "\n";
        pcap_freealldevs(all_devices);
        return 1;
    }
    pcap_freealldevs(all_devices);
    }

    std::unique_ptr<TrafficGrpcClient> grpc_client;
    if (use_grpc) {
        const char* grpc_addr_env = std::getenv("GRPC_SERVER_ADDR");
        std::string grpc_addr = grpc_addr_env ? grpc_addr_env : "localhost:50051";
        std::cout << "[grpc] Connecting to " << grpc_addr << "...\n";
        grpc_client = std::make_unique<TrafficGrpcClient>(grpc_addr);
        if (!grpc_client->start_session("capture-session-1", interface_name)) {
            std::cerr << "[grpc] Could not start session. Is test_server.exe running?\n";
            return 1;
        }
        std::cout << "[grpc] Session started, streaming packets...\n";
    }

    std::cout << "\nCapturing (async, via Boost Asio) on: " << interface_name
              << "\nThis will run for 30 seconds, then stop automatically.\n";
    if (use_grpc) {
        std::cout << "Streaming to gRPC server at localhost:50051\n";
    }

    boost::asio::io_context io_context;
    AsyncCapture capture(io_context, handle, grpc_client.get());

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

    if (use_grpc && grpc_client) {
        grpc_client->finish_session();
    }

    return 0;
}
