#ifndef ANOMALY_DETECTOR_H
#define ANOMALY_DETECTOR_H

#include "PacketTypes.h"
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <chrono>
#include <cstddef>

class AnomalyDetector {
private:
    struct BurstTracker {
        std::queue<std::chrono::system_clock::time_point> recentPackets;
        static const std::size_t BURST_THRESHOLD = 100;
        static const int BURST_WINDOW_SECONDS = 5;
    };
    
    struct ScanTracker {
        std::unordered_set<uint16_t> scannedPorts;
        std::chrono::system_clock::time_point firstScanTime;
        static const std::size_t SCAN_THRESHOLD = 10;
        static const int SCAN_WINDOW_SECONDS = 30;
    };
    
    struct ConnectionTracker {
        int failedAttempts = 0;
        std::chrono::system_clock::time_point firstFailTime;
        static const int FAILED_THRESHOLD = 20;
        static const int FAILED_WINDOW_SECONDS = 60;
    };
    
    std::unordered_map<std::string, BurstTracker> burstTrackers;
    std::unordered_map<std::string, ScanTracker> scanTrackers;
    std::unordered_map<std::string, ConnectionTracker> connectionTrackers;
    
    void cleanupOldEntries();
    bool isPacketBurst(const std::string& sourceIP);
    bool isPortScan(const PacketInfo& packet);
    bool isFailedConnection(const PacketInfo& packet);
    
public:
    AnomalyDetector() = default;
    
    bool analyzePacket(PacketInfo& packet);
    void reset();
    void printStats() const;
};

#endif 
