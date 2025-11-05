#include "websocket_server.h"

#include <common/constants.h>
#include <common/protocol/packet_codec.h>
#include <hv/WebSocketServer.h>
#include <plog/Log.h>

#include <algorithm>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "../handlers/handler_registry.h"
#include "hv/WebSocketChannel.h"

std::shared_ptr<hv::WebSocketServer> server;
std::vector<WebSocketChannelPtr> channels;
std::mutex channels_mutex;
std::mutex send_mutex, receive_mutex;
std::vector<std::shared_ptr<packet> > send_queued_packets, receive_queued_packets;

void websocket_server::run_server(std::condition_variable& locker, int port) {
	hv::WebSocketService service;
        service.onopen = [&](const WebSocketChannelPtr& channel, const HttpRequestPtr& req) {
                PLOGD.printf("A connection established");
                {
                        std::lock_guard<std::mutex> lock(channels_mutex);
                        channels.push_back(channel);
                }
                locker.notify_one();
        };
        service.onmessage = [](const WebSocketChannelPtr& channel, const std::string& msg) {
                std::lock_guard<std::mutex> lock(receive_mutex);
                read_stream stream(msg.data(), msg.size());
                auto packet = packet_codec::decode(stream);
                if (packet) {
                        receive_queued_packets.push_back(packet);
                } else {
                        PLOGF.printf("Invalid packet retrieved");
                }
                stream.close();
        };
        service.onclose = [&](const WebSocketChannelPtr& channel) {
                PLOGI.printf("A connection closed");
                std::lock_guard<std::mutex> lock(channels_mutex);
                channels.erase(std::remove(channels.begin(), channels.end(), channel), channels.end());
        };

	server = std::make_shared<hv::WebSocketServer>(&service);
	server->setHost();
	server->setPort(port);
	server->setThreadNum(4);
	server->run();
}

void websocket_server::launch(int port) {
	PLOGI.printf("Starting server on %d", port);
	std::condition_variable locker;
	std::thread([&]() {
		run_server(locker, port);
	}).detach();

	PLOGI.printf("Waiting for a connection...");
	std::mutex mutex;
	std::unique_lock lock(mutex);
	locker.wait(lock);
}

void websocket_server::send_packet(const std::shared_ptr<packet>& packet) {
        std::lock_guard<std::mutex> lock(send_mutex);
        send_queued_packets.push_back(packet);
}

void websocket_server::tick() {
	performReceive();
	performSend();
}

void websocket_server::performSend() {
        std::vector<std::shared_ptr<packet> > packets_to_send;
        {
                std::lock_guard<std::mutex> lock(send_mutex);
                packets_to_send.swap(send_queued_packets);
        }

        if (packets_to_send.empty()) {
                return;
        }

        std::vector<WebSocketChannelPtr> current_channels;
        {
                std::lock_guard<std::mutex> lock(channels_mutex);
                current_channels = channels;
        }

        for (auto& packet : packets_to_send) {
                write_stream stream = packet_codec::encode(packet);
                auto buf = stream.as_buffer();
                for (auto& channel : current_channels) {
                        channel->send(static_cast<char*>(buf.data), buf.size, WS_OPCODE_BINARY);
                }
                buf.free();
        }
}

void websocket_server::performReceive() {
        std::vector<std::shared_ptr<packet> > packets_to_process;
        {
                std::lock_guard<std::mutex> lock(receive_mutex);
                packets_to_process.swap(receive_queued_packets);
        }

        for (const auto& packet : packets_to_process) {
                if (const auto handler = handler_registry::get_handler_by_id(packet->get_id())) {
                        handler(packet);
                }
        }
}
