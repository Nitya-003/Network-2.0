#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

#include "PacketTypes.h"
#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <memory>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <pcap.h>
#else
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#endif

class PacketCapture {
private:
    pcap_t* handle;
    std::string interface;
    std::atomic<bool> isCapturing{false};

    // ===== RING BUFFER =====
    static const int RING_SIZE = 2048;   // bigger buffer for high speed
    // const u_char* ringBuffer[RING_SIZE]; Naming conflict. (see 7 line below)

    struct QueuedPacket {
        struct pcap_pkthdr header;
        std::unique_ptr<u_char[]> data;
    };

    std::unique_ptr<QueuedPacket> ringBuffer[RING_SIZE];

    std::atomic<size_t> ringHead{0};
    std::atomic<size_t> ringTail{0};

    static void packetHandler(
        u_char* userData,
        const struct pcap_pkthdr* pkthdr,
        const u_char* packet
    );

    PacketInfo parsePacket(const struct pcap_pkthdr* pkthdr,
                           const u_char* packet);

    std::string ipToString(uint32_t ip);

    // new worker-style processor
    void processRingBuffer();

public:
    PacketCapture();
    ~PacketCapture();

    bool initialize(const std::string& interface = "");
    bool startCapture();
    void stopCapture();
    std::vector<std::string> getAvailableInterfaces();

    std::function<void(const PacketInfo&)> onPacketReceived;

    bool isActive() const { return isCapturing.load(); }
    const std::string& getInterface() const { return interface; }
};

#endif
