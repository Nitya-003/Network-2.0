# Network 2.0

<p align="center">
    <img src="https://img.shields.io/badge/DSCWoC-2026-blueviolet?style=for-the-badge&logo=rocket" alt="DSCWoC Badge">
    <img src="https://img.shields.io/badge/Mission-Open%20Source-ff69b4?style=for-the-badge&logo=github" alt="Mission Badge">
  </p>

Advanced C++ command-line network utility for real-time packet monitoring with intelligent anomaly detection.

## Features

- **Real-time Packet Capture**: Uses libpcap for efficient packet capture across Windows and Linux
- **Live Traffic Display**: Well-formatted table showing source IP, destination IP, protocol, packet size, and timestamps
- **Intelligent Anomaly Detection**: Built-in heuristics for detecting:
  - Unusual packet bursts (>100 packets in 5 seconds)
  - Port scanning behavior (>10 ports scanned in 30 seconds)
  - Repeated failed connection attempts (>20 failures in 60 seconds)
- **Watch Rules**: Set custom alerts for specific IPs and ports with audio notifications
- **Color-coded Output**: Visual indicators for anomalies and watched traffic
- **CSV Export**: Export captured data for later analysis
- **Cross-platform**: Works on both Windows and Linux systems

## Building

### Prerequisites

**Linux:**
```bash
sudo apt-get install libpcap-dev cmake build-essential
```

**Windows:**
- Install WinPcap or Npcap
- Visual Studio 2019 or later
- CMake 3.15+

### Build Instructions

```bash
mkdir build && cd build
cmake ..
make
```

**Windows (Visual Studio):**
```cmd
mkdir build && cd build
cmake .. -G "Visual Studio 16 2019"
cmake --build . --config Release
```

## Usage

### Basic Usage
```bash
./network2.0
```

### Command Line Options
```bash
./network2.0 --watch-ip 192.168.1.10 --alert-port 8080 --log traffic.csv
```

Available options:
- `--watch-ip <IP>`: Watch traffic for specific IP address
- `--alert-port <PORT>`: Alert on traffic to/from specific port
- `--log <filename>`: Enable logging to CSV file
- `--interface <name>`: Specify network interface
- `--protocol <TYPE>`: Filter by protocol (TCP, UDP, ICMP)
- `--help`: Show help message

### Interactive Commands

While the program is running, you can use these commands:

- `h, help`: Show help message
- `s, stats`: Display detailed network statistics
- `w, watch`: Show current watch rules
- `a, anomalies`: Show anomaly detection status
- `r, reset`: Reset all statistics
- `l, log <filename>`: Enable/disable logging
- `e, export <filename>`: Export captured data to CSV
- `q, quit`: Exit the program

## Examples

### Monitor specific IP address
```bash
./network2.0 --watch-ip 192.168.1.100
```

### Alert on web traffic with logging
```bash
./network2.0 --alert-port 80 --alert-port 443 --log web_traffic.csv
```

### Monitor specific interface
```bash
./network2.0 --interface eth0 --log network_capture.csv
```

### Filter by protocol
```bash
./network2.0 --protocol TCP
./network2.0 --protocol ICMP --log icmp_traffic.csv
```

## Output Interpretation

### Live Traffic Table

The main display shows:
- **Time**: Timestamp of packet capture
- **Source IP**: Source IP address
- **Source MAC**: Source hardware (MAC) address
- **Dest IP**: Destination IP address
- **Dest MAC**: Destination hardware (MAC) address
- **Protocol**: TCP, UDP, ICMP, or other
- **Size**: Packet size in bytes
- **Notes**: Anomaly information or alerts

### Color Coding

- **White**: Normal traffic
- **Red**: Anomalous packets (bursts, scans, failed connections)
- **Yellow**: Watched IP/port traffic
- **Cyan**: Headers and informational text
- **Green**: Success messages

### Anomaly Detection

The tool detects three types of anomalies:

1. **Packet Bursts**: More than 100 packets from same source in 5 seconds
2. **Port Scans**: More than 10 different ports accessed from same source in 30 seconds  
3. **Failed Connections**: More than 20 small TCP packets from same source in 60 seconds

## CSV Export Format

Exported CSV files contain:
```
Timestamp,Source_IP,Source_Port,Dest_IP,Dest_Port,Source_MAC,Dest_MAC,Protocol,Size_Bytes,Is_Anomaly,Anomaly_Reason
```

## Architecture

The application uses a modular design with these components:

- `PacketCapture`: Handles low-level packet capture using libpcap
- `AnomalyDetector`: Implements heuristic-based anomaly detection
- `NetworkStats`: Tracks and displays network statistics
- `WatchRules`: Manages IP and port watch rules with alerting
- `Logger`: Handles CSV logging and data export
- `Utils`: Common utilities for formatting and cross-platform operations

## Limitations

- Requires administrator/root privileges for packet capture
- Network interface must support promiscuous mode
- Performance depends on network traffic volume and system capabilities

## Contributing & Community

We welcome contributions from the community! To keep our project healthy and inclusive, please refer to the following documents:
* **[Contributing Guidelines](CONTRIBUTING.md)**: Learn how to set up your dev environment, our coding standards, and the process for submitting Pull Requests.
* **[Code of Conduct](CODE_OF_CONDUCT.md)**: Our standards for maintaining a respectful and welcoming environment.
* **[Security Policy](SECURITY.md)**: Guidelines on how to report security vulnerabilities responsibly.

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

## Security Notice

This tool is designed for legitimate network monitoring and security analysis. Always ensure you have proper authorization before monitoring network traffic.
