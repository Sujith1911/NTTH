# Packet Sniffing & Attack Detection

> Last updated: 2026-05-02

## Traffic Capture Pipeline

### Main NIC Sniffer (`app/monitor/packet_sniffer.py`)
- **Interface**: `wlp0s20f3` (main WiFi, managed mode)
- **Mode**: Promiscuous (`promisc=True`)
- **BPF Filter**: `ip` (all IP traffic)
- **Engine**: Scapy `AsyncSniffer` — runs in thread-pool executor
- **Callback**: Each packet → `extract_features()` → `device_seen` event

### AR9271 WiFi Sniffer (`app/wireless/wifi_sniffer.py`)
- **Interface**: `wlx24ec99bfe292` (USB adapter, monitor mode)
- **Mode**: 802.11 raw frame capture
- **Captures**: Beacons, probe requests, deauth frames
- **Channel Hopping**: Cycles channels 1-13 every 0.5s

### Network Scanner (`app/monitor/network_scanner.py`)
- **Method**: ICMP ping sweep → ARP cache → hostname resolution
- **Frequency**: Every 60 seconds
- **Subnet**: `10.223.251.0/24` (auto-detected)
- **Port Scanning**: 28 common ports per discovered device
- **Ports Scanned**: 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 5985, 6379, 8080, 8443, 8888, 9200, 27017

## Feature Extraction (`app/monitor/feature_extractor.py`)

Each packet is parsed into 8 features:

| Feature | Type | Description |
|---------|------|-------------|
| `src_ip` | str | Source IP address |
| `dst_ip` | str | Destination IP address |
| `pkt_len` | int | Packet length in bytes |
| `protocol` | str | tcp / udp / icmp / other |
| `dst_port` | int | Destination port |
| `src_port` | int | Source port |
| `flags` | str | TCP flags (SYN, ACK, RST, etc.) |
| `is_syn` / `is_ack` / `is_rst` | bool | Flag decomposition |

## IDS Rule Engine (`app/ids/rule_engine.py`)

### Port Scan Detection
- **Window**: 15 seconds sliding
- **Threshold**: 4+ unique destination ports from same source
- **Score**: 0.6-0.9 based on port count

### SYN Flood Detection
- **Window**: 1 second
- **Threshold**: 30+ SYN packets/second from same source
- **Score**: 0.8-1.0 based on rate

### Brute Force Detection
- **Window**: 120 seconds
- **Threshold**: 3+ connection attempts to auth ports (21, 22, 23, 3389, 5900)
- **Score**: 0.7-0.95 based on attempt count

## ML Anomaly Model (`app/ids/anomaly_model.py`)

- **Algorithm**: Isolation Forest (scikit-learn)
- **Trees**: 200 estimators
- **Training**: Auto-trains on first 500 normal packets
- **Features**: pkt_len, dst_port, is_syn, is_ack, is_rst, protocol_encoded
- **Output**: Anomaly score 0.0-1.0

## Risk Calculation (`app/ids/risk_calculator.py`)

```
risk_score = 0.6 × rule_score + 0.4 × ml_score
```

| Risk Score | Action |
|-----------|--------|
| < 0.2 | Allow (no action) |
| 0.2 - 0.35 | Log |
| 0.35 - 0.45 | Rate Limit |
| 0.45 - 0.95 | Honeypot Redirect |
| ≥ 0.95 | Block |

## Data Flow

```
Packet → Feature Extractor → Threat Agent (IDS + ML + GeoIP)
                                    │
                                    ▼ risk > 0.2
                              Decision Agent
                                    │
                    ┌───────────────┼──────────────┐
                    ▼               ▼              ▼
              Rate Limit      Honeypot          Block
              (nftables)    (redirect +       (nftables
                           auto-deploy)        drop)
                                    │
                                    ▼
                            Reporting Agent
                            (DB + WebSocket)
                                    │
                                    ▼
                            Flutter Dashboard
```
