#ifndef PACKET_TYPES_H
#define PACKET_TYPES_H

#include <string>
#include <chrono>
#include <cstdint>

struct PacketInfo {
    std::string sourceIP;
    std::string destIP;
    std::string sourceMAC;
    std::string destMAC;
    std::string protocol;
    uint16_t sourcePort;
    uint16_t destPort;
    uint32_t packetSize;
    std::chrono::system_clock::time_point timestamp;
    bool isAnomaly;
    std::string anomalyReason;
    std::string dnsQuery;
    
    PacketInfo() : sourcePort(0), destPort(0), packetSize(0), isAnomaly(false) {
        timestamp = std::chrono::system_clock::now();
    }
};

enum class AlertType {
    IP_WATCH,
    PORT_WATCH,
    PACKET_BURST,
    PORT_SCAN,
    FAILED_CONNECTIONS
};

struct Alert {
    AlertType type;
    std::string message;
    std::chrono::system_clock::time_point timestamp;
    PacketInfo packet;
};

enum class Protocol {
    TCP = 6,
    UDP = 17,
    ICMP = 1,
    OTHER = 0
};

#endif
