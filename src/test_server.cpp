#include <grpcpp/grpcpp.h>
#include "packet_event.grpc.pb.h"
#include <iostream>

class PacketIngestServiceImpl final : public traffic::PacketIngest::Service {
    grpc::Status StreamPackets(grpc::ServerContext* context,
                                grpc::ServerReader<traffic::IngestMessage>* reader,
                                traffic::IngestSummary* summary) override {
        traffic::IngestMessage msg;
        int64_t packets = 0;
        int64_t alerts = 0;

        while (reader->Read(&msg)) {
            if (msg.has_session_info()) {
                const auto& info = msg.session_info();
                std::cout << "[server] Session started: " << info.session_id()
                          << " on interface " << info.interface_name() << "\n";
            } else if (msg.has_packet_event()) {
                const auto& event = msg.packet_event();
                packets++;
                if (event.alerts_size() > 0) {
                    alerts += event.alerts_size();
                    std::cout << "[server] ALERT packet #" << packets << ": "
                              << event.source_ip() << " -> " << event.dest_ip()
                              << " (" << event.alerts(0) << ")\n";
                } else if (packets % 100 == 0) {
                    std::cout << "[server] ...received " << packets << " packets so far\n";
                }
            }
        }

        summary->set_packets_received(packets);
        summary->set_alerts_received(alerts);
        std::cout << "[server] Stream closed. Total: " << packets
                  << " packets, " << alerts << " alerts\n";
        return grpc::Status::OK;
    }
};

int main() {
    std::string server_address("0.0.0.0:50051");
    PacketIngestServiceImpl service;

    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);

    std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
    std::cout << "Test gRPC server listening on " << server_address << "\n";
    std::cout << "(This is throwaway scaffolding - Phase 6 replaces it with Java/Spring Boot)\n";
    server->Wait();

    return 0;
}
