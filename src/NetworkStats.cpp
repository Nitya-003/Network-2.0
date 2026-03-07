#include "NetworkStats.h"
#include "Utils.h"
#include <iostream>
#include <iomanip>

NetworkStats::NetworkStats() : totalPackets(0), totalBytes(0), anomalousPackets(0) {
    startTime = std::chrono::system_clock::now();
    lastPacketTime = startTime;
}

void NetworkStats::recordPacket(const PacketInfo& packet) {
    totalPackets++;
    totalBytes += packet.packetSize;
    lastPacketTime = packet.timestamp;
    
    if (packet.isAnomaly) {
        anomalousPackets++;
    }
    
    protocolCounts[packet.protocol]++;
    
    ipCounts[packet.sourceIP]++;
    if (packet.sourceIP != packet.destIP) {
        ipCounts[packet.destIP]++;
    }
}

void NetworkStats::reset() {
    totalPackets = 0;
    totalBytes = 0;
    anomalousPackets = 0;
    protocolCounts.clear();
    ipCounts.clear();
    startTime = std::chrono::system_clock::now();
}

double NetworkStats::getPacketsPerSecond() const {
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        lastPacketTime - startTime).count();
    if (elapsed == 0) return 0.0;
    return static_cast<double>(totalPackets) / elapsed;
}

void NetworkStats::printStats() const {
    std::cout << Utils::Colors::BOLD << "\n=== Network Statistics ===" << Utils::Colors::RESET << std::endl;
    std::cout << "Total packets: " << totalPackets << std::endl;
    std::cout << "Total bytes: " << Utils::formatBytes(totalBytes) << std::endl;
    std::cout << "Anomalous packets: " << Utils::Colors::RED << anomalousPackets 
              << Utils::Colors::RESET << " (" << std::fixed << std::setprecision(2)
              << (totalPackets > 0 ? (double)anomalousPackets / totalPackets * 100 : 0.0) 
              << "%)" << std::endl;
    std::cout << "Packets/sec: " << std::fixed << std::setprecision(2) 
              << getPacketsPerSecond() << std::endl;
    
    if (!protocolCounts.empty()) {
        std::cout << "\nProtocol distribution:" << std::endl;
        for (const auto& pair : protocolCounts) {
            std::cout << "  " << pair.first << ": " << pair.second 
                     << " (" << std::fixed << std::setprecision(1)
                     << (double)pair.second / totalPackets * 100 << "%)" << std::endl;
        }
    }
}

void NetworkStats::printLiveTable(const PacketInfo* recentPackets, size_t count) const {
    Utils::clearScreen();
    
    std::cout << Utils::Colors::BOLD << Utils::Colors::CYAN 
              << "=== Network 2.0 - Live Traffic ===" 
              << Utils::Colors::RESET << std::endl;
    
    std::cout << "Packets: " << totalPackets << " | Bytes: " << Utils::formatBytes(totalBytes)
              << " | Anomalies: " << Utils::Colors::RED << anomalousPackets << Utils::Colors::RESET
              << " | Rate: " << std::fixed << std::setprecision(1) << getPacketsPerSecond() << " pps"
              << std::endl << std::endl;
    
    std::cout << Utils::Colors::BOLD;
    std::cout << std::left << std::setw(12) << "Time"
              << std::setw(16) << "Source IP"
              << std::setw(18) << "Source MAC"
              << std::setw(16) << "Dest IP"
              << std::setw(18) << "Dest MAC"
              << std::setw(8) << "Protocol"
              << std::setw(10) << "Size"
              << std::setw(30) << "Notes"
              << Utils::Colors::RESET << std::endl;
    
    std::cout << std::string(128, '-') << std::endl;
    

    for (size_t i = 0; i < count; ++i) {
        const auto& packet = recentPackets[i];
        
        std::string color = Utils::Colors::WHITE;
        if (packet.isAnomaly) {
            color = Utils::Colors::RED;
        }
        
        std::cout << color;
        std::cout << std::left << std::setw(12) << Utils::formatTimestamp(packet.timestamp)
                  << std::setw(16) << packet.sourceIP
                  << std::setw(18) << packet.sourceMAC
                  << std::setw(16) << packet.destIP
                  << std::setw(18) << packet.destMAC
                  << std::setw(8) << packet.protocol
                  << std::setw(10) << Utils::formatBytes(packet.packetSize);
        
        if (packet.isAnomaly) {
            std::cout << std::setw(30) << ("ANOMALY: " + packet.anomalyReason);
        } else if (!packet.dnsQuery.empty()) {
            std::string notes = "DNS: " + packet.dnsQuery;
            if (notes.length() > 29) {
                notes = notes.substr(0, 26) + "...";
            }
            std::cout << std::setw(30) << notes;
        } else {
            std::cout << std::setw(30) << "";
        }
        
        std::cout << Utils::Colors::RESET << std::endl;
    }
}
