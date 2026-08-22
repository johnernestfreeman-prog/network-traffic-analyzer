#pragma once

#include <grpcpp/grpcpp.h>
#include "packet_event.grpc.pb.h"
#include <memory>
#include <string>
#include <chrono>
#include <iostream>

class TrafficGrpcClient {
public:
    TrafficGrpcClient(const std::string& server_address) {
        channel_ = grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials());
        stub_ = traffic::PacketIngest::NewStub(channel_);
    }

    bool start_session(const std::string& session_id, const std::string& interface_name) {
        stream_ = stub_->StreamPackets(&context_, &summary_);
        if (!stream_) {
            std::cerr << "  [grpc] Failed to open stream\n";
            return false;
        }

        traffic::IngestMessage msg;
        auto* session_info = msg.mutable_session_info();
        session_info->set_session_id(session_id);
        session_info->set_interface_name(interface_name);
        session_info->set_started_unix_ms(now_ms());

        bool ok = stream_->Write(msg);
        if (!ok) {
            std::cerr << "  [grpc] Failed to send session info - is the server running?\n";
        }
        return ok;
    }

    bool send_packet(const std::string& src_ip, const std::string& dst_ip,
                      uint16_t src_port, uint16_t dst_port,
                      const std::string& protocol, uint32_t length_bytes,
                      const std::string& tcp_flags,
                      const std::vector<std::string>& alerts) {
        if (!stream_) return false;

        traffic::IngestMessage msg;
        auto* event = msg.mutable_packet_event();
        event->set_source_ip(src_ip);
        event->set_dest_ip(dst_ip);
        event->set_source_port(src_port);
        event->set_dest_port(dst_port);
        event->set_protocol(protocol);
        event->set_length_bytes(length_bytes);
        event->set_tcp_flags(tcp_flags);
        event->set_timestamp_unix_ms(now_ms());
        for (const auto& alert : alerts) {
            event->add_alerts(alert);
        }

        return stream_->Write(msg);
    }

    bool finish_session() {
        if (!stream_) return false;
        stream_->WritesDone();
        grpc::Status status = stream_->Finish();
        if (!status.ok()) {
            std::cerr << "  [grpc] Stream finished with error: " << status.error_message() << "\n";
            return false;
        }
        std::cout << "  [grpc] Server confirmed receipt: " << summary_.packets_received()
                  << " packets, " << summary_.alerts_received() << " alerts\n";
        return true;
    }

private:
    static int64_t now_ms() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    std::shared_ptr<grpc::Channel> channel_;
    std::unique_ptr<traffic::PacketIngest::Stub> stub_;
    grpc::ClientContext context_;
    traffic::IngestSummary summary_;
    std::unique_ptr<grpc::ClientWriter<traffic::IngestMessage>> stream_;
};
