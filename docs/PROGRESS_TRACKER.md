# NTTH — Progress Tracker & Remaining Work

> Last updated: 2026-05-02

---

## Section A: What's Built and Working (90%)

### Core Backend (100% ✅)

| # | Component | File | Status | Proof |
|---|-----------|------|--------|-------|
| 1 | FastAPI server | `app/main.py` | ✅ Done | Running on port 8001 natively |
| 2 | JWT auth (login/refresh) | `app/core/auth.py` | ✅ Done | admin/NtthAdmin2026 working |
| 3 | SQLite database (dev) | `ntth.db` | ✅ Done | Persistent across restarts |
| 4 | SQLAlchemy models + CRUD | `app/database/` | ✅ Done | All tables + safe migrations |
| 5 | REST API (15+ endpoints) | `app/api/` | ✅ Done | Verified via curl |
| 6 | WebSocket live updates | `app/websocket/` | ✅ Done | Real-time push to dashboard |
| 7 | Structured logging | `app/core/logger.py` | ✅ Done | JSON logs to file + console |
| 8 | Configuration system | `app/config.py` | ✅ Done | Pydantic settings + .env |
| 9 | Login rate limiting | `app/core/auth.py` | ✅ Done | 5 attempts / 5 min per IP |

### Packet Capture & IDS (100% ✅)

| # | Component | File | Status | Details |
|---|-----------|------|--------|---------|
| 10 | Scapy packet sniffer | `app/monitor/packet_sniffer.py` | ✅ Done | AsyncSniffer on wlp0s20f3, **promiscuous mode** |
| 11 | Feature extractor | `app/monitor/feature_extractor.py` | ✅ Done | 8 features: src_ip, dst_port, flags... |
| 12 | Device registry | `app/monitor/device_registry.py` | ✅ Done | Per-IP packet/SYN/port counts |
| 13 | Network scanner (ARP+Ping) | `app/monitor/network_scanner.py` | ✅ Done | LAN device discovery + **port scanning** |
| 14 | **Port scanner** | `app/monitor/network_scanner.py` | ✅ **NEW** | 28-port TCP connect scan on ALL discovered devices |
| 15 | Port scan detector | `app/ids/rule_engine.py` | ✅ Done | 4 unique ports in 15s window |
| 16 | SYN flood detector | `app/ids/rule_engine.py` | ✅ Done | 30 SYN/sec threshold |
| 17 | Brute force detector | `app/ids/rule_engine.py` | ✅ Done | 3 attempts in 120s to auth ports |
| 18 | Isolation Forest ML | `app/ids/anomaly_model.py` | ✅ Done | 200 trees, trains on 500 samples |
| 19 | Risk calculator | `app/ids/risk_calculator.py` | ✅ Done | 0.6×rule + 0.4×ml |
| 20 | GeoIP lookup | `app/geoip/geo_lookup.py` | ✅ Done | MaxMind GeoLite2 City + ASN |

### AI Agent Pipeline (100% ✅)

| # | Component | File | Status | Details |
|---|-----------|------|--------|---------|
| 21 | Event bus (pub/sub) | `app/core/event_bus.py` | ✅ Done | asyncio.Queue, 5000 capacity |
| 22 | Threat Agent | `app/agents/threat_agent.py` | ✅ Done | IDS + ML + GeoIP enrichment |
| 23 | Decision Agent | `app/agents/decision_agent.py` | ✅ Done | Risk→action, protocol-aware routing |
| 24 | Enforcement Agent | `app/agents/enforcement_agent.py` | ✅ Done | nftables + redirect + **auto-deploy honeypot** |
| 25 | Reporting Agent | `app/agents/reporting_agent.py` | ✅ Done | DB persist + WS broadcast |
| 26 | Feedback Agent | `app/agents/feedback_agent.py` | ✅ Done | FP tracking + honeypot engagement |

### Firewall (100% ✅)

| # | Component | File | Status | Details |
|---|-----------|------|--------|---------|
| 27 | nftables manager | `app/firewall/nft_manager.py` | ✅ Done | block, rate_limit, redirect |
| 28 | Rule tracker | `app/firewall/rule_tracker.py` | ✅ Done | Deduplication + DB tracking |
| 29 | Rule cleanup | `app/firewall/rule_cleanup.py` | ✅ Done | Auto-expire after TTL |

### Honeypot System (100% ✅)

| # | Component | File | Status | Details |
|---|-----------|------|--------|---------|
| 30 | Cowrie SSH honeypot | Docker `ntth_cowrie` | ✅ Done | Port 30022, captures commands |
| 31 | Cowrie log watcher | `app/honeypot/cowrie_watcher.py` | ✅ Done | Tails cowrie.json in real-time |
| 32 | Session logger | `app/honeypot/session_logger.py` | ✅ Done | DB + WS + GeoIP |
| 33 | HTTP honeypot | `app/honeypot/http_honeypot.py` | ✅ Done | Port 8888, logs probes |
| 34 | **Multi-protocol honeypot** | `app/honeypot/multi_honeypot.py` | ✅ **NEW** | FTP, Telnet, MySQL, RDP, VNC, SMB, Redis, MongoDB |
| 35 | **Auto-deploy on startup** | `app/main.py` | ✅ **NEW** | 8 honeypots pre-deployed at boot |
| 36 | **Dynamic attack-port deploy** | `app/agents/enforcement_agent.py` | ✅ **NEW** | Honeypot auto-spawns on any attacked port |
| 37 | Cowrie controller | `app/honeypot/cowrie_controller.py` | ✅ Done | Docker API start/stop |

### Wireless / AR9271 Monitoring (100% ✅)

| # | Component | File | Status | Details |
|---|-----------|------|--------|---------|
| 38 | **Auto-monitor setup** | `app/wireless/auto_monitor.py` | ✅ Done | Safe `nmcli` disconnect (no `airmon-ng kill`) |
| 39 | WiFi sniffer | `app/wireless/wifi_sniffer.py` | ✅ Done | 802.11 frame capture on AR9271 |
| 40 | Channel hopper | `app/wireless/channel_hopper.py` | ✅ Done | Channels 1-13 cycling |
| 41 | Probe request tracker | `app/wireless/probe_tracker.py` | ✅ Done | MAC-based device tracking |
| 42 | Deauth detector | `app/wireless/deauth_detector.py` | ✅ Done | Threshold-based alerting |
| 43 | Rogue AP detector | `app/wireless/rogue_ap_detector.py` | ✅ Done | SSID whitelist comparison |
| 44 | Persistent tracker | `app/wireless/persistent_tracker.py` | ✅ Done | MAC persistence to disk |
| 45 | Wireless API (8 endpoints) | `app/api/routes_wireless.py` | ✅ Done | Stats, probes, deauth, rogue, status |

### Flutter Dashboard (100% ✅)

| # | Component | File | Status | Details |
|---|-----------|------|--------|---------|
| 46 | Login screen | `screens/login_screen.dart` | ✅ Done | JWT auth, server URL |
| 47 | Dashboard screen | `screens/dashboard_screen.dart` | ✅ Done | Overview cards + wireless stats |
| 48 | Threat Map | `screens/threat_map_screen.dart` | ✅ Done | LIVE/RECENT badges, risk chips |
| 49 | Firewall Rules | `screens/firewall_screen.dart` | ✅ Done | NEW/EXPIRED, Active/History |
| 50 | Honeypot Sessions | `screens/honeypot_screen.dart` | ✅ Done | Terminal command display |
| 51 | Network Topology | `screens/topology_screen.dart` | ✅ Done | ARP device list |
| 52 | **Wireless screen** | `screens/wireless_screen.dart` | ✅ Done | Probes, deauth, rogue APs |
| 53 | **Packet Inspector** | `screens/packet_inspector_screen.dart` | ✅ Done | Real-time captured packet view |
| 54 | System Info | `screens/system_screen.dart` | ✅ Done | Agent status + health |
| 55 | Settings | `screens/settings_screen.dart` | ✅ Done | Configuration management |
| 56 | WebSocket service | `core/websocket_service.dart` | ✅ Done | Auto-reconnect |
| 57 | Dark theme | `theme/app_theme.dart` | ✅ Done | Glassmorphism effects |
| 58 | App settings (port 8001) | `core/app_settings.dart` | ✅ Done | Synced with backend |

### Infrastructure & Deployment (100% ✅)

| # | Component | File | Status | Details |
|---|-----------|------|--------|---------|
| 59 | Startup script | `start.sh` | ✅ Done | Port conflict resolution + auto-detect WiFi |
| 60 | Environment config | `backend/.env` | ✅ Done | All settings externalized |
| 61 | Simulation disabled | `.env` | ✅ Done | `ENABLE_SIMULATION_ROUTES=false` |
| 62 | DB migration | `app/main.py` | ✅ Done | Safe ALTER TABLE on startup |
| 63 | Data cleanup tools | `cleanup_fake_data.py` | ✅ Done | Purges test/fake data |

### Data Integrity (100% ✅)

| # | Verification | Result |
|---|-------------|--------|
| 64 | Captured packets | ✅ All from `10.223.251.*` (real subnet) |
| 65 | Threat events | ✅ All from live IDS pipeline |
| 66 | Fake data check | ✅ Zero `10.142.204.*` or simulation IPs found |
| 67 | Simulation route | ✅ Permanently disabled |

---

## Section B: What's Left (10%)

### 🔴 CRITICAL (For research paper)

| # | Task | Effort | Time | Priority |
|---|------|--------|------|----------|
| 68 | Run detection rate experiments (50 runs × 4 attack types) | Medium | 2 days | P0 |
| 69 | Measure end-to-end response latency T1→T4 (200 packets) | Medium | 1 day | P0 |
| 70 | Install Snort + Suricata, run identical attack comparison | Medium | 2 days | P0 |
| 71 | Ablation study: grid search weights + ROC curves | Medium | 1 day | P0 |
| 72 | Multi-model comparison (RF, SVM, KNN, DT vs IF) | Medium | 2 days | P0 |
| 73 | Collect 10,000+ real packets (attack + normal) | Large | 3 days | P0 |
| 74 | Validate on CICIDS2017 benchmark | Medium | 2 days | P0 |
| 75 | Write research paper (IEEE format) | Large | 7 days | P0 |

### 🟢 NICE TO HAVE

| # | Task | Effort | Time | Priority |
|---|------|--------|------|----------|
| 76 | Add basic pytest tests for rule_engine + risk_calculator | Small | 1 day | P2 |
| 77 | Tighten CORS origins for production | Small | 1 hr | P2 |
| 78 | GitHub repo cleanup for reproducibility | Small | 1 day | P2 |
| 79 | Generate ROC curve plots + confusion matrix visuals | Small | 1 day | P2 |

---

## Section C: Current Progress

```
SYSTEM IMPLEMENTATION   ████████████████████  100%  (items 1-67)
WIRELESS (AR9271)       ████████████████████  100%  (items 38-45)
HONEYPOT SYSTEM         ████████████████████  100%  (items 30-37)
PORT SCANNING           ████████████████████  100%  (item 14)
FLUTTER DASHBOARD       ████████████████████  100%  (items 46-58)
DATA INTEGRITY          ████████████████████  100%  (items 64-67)
EXPERIMENTS             ░░░░░░░░░░░░░░░░░░░░    0%  (items 68-74)
PAPER WRITING           ████████████████░░░░   75%  (item 75)
─────────────────────────────────────────────────
OVERALL                 ██████████████████░░   90%
```

---

## Section D: Feature Timeline

### Phase 1 — Core System (Complete ✅)
- [x] FastAPI + SQLAlchemy + JWT auth
- [x] Scapy packet capture + IDS rule engine
- [x] Isolation Forest ML anomaly detection
- [x] 6-agent AI pipeline (Threat → Decision → Enforcement → Reporting → Feedback)
- [x] nftables firewall (block, rate-limit, redirect)
- [x] Cowrie SSH + HTTP honeypot
- [x] Flutter 10-screen dashboard + WebSocket

### Phase 2 — AR9271 Wireless (Complete ✅)
- [x] Auto-detect AR9271 USB adapter (`wlx` prefix)
- [x] Safe monitor mode setup (nmcli disconnect, no airmon-ng kill)
- [x] 802.11 frame capture (beacons, probes, deauth)
- [x] Channel hopping (1-13)
- [x] Probe request tracking + deauth detection + rogue AP detection
- [x] Wireless dashboard screen + API endpoints

### Phase 3 — Autonomous Defense (Complete ✅) — May 2026
- [x] **Port scanning** all discovered devices (28 common ports)
- [x] **Open ports stored** per device in DB (persistent)
- [x] **Multi-protocol honeypots** auto-deployed at startup (FTP, Telnet, MySQL, RDP, VNC, SMB, Redis, MongoDB)
- [x] **Dynamic honeypot deployment** on any attacked port
- [x] **Promiscuous mode** sniffer for wider traffic capture
- [x] **Simulation routes disabled** — only real data in DB
- [x] **Safe DB migrations** — new columns added without data loss
- [x] **2.4GHz band support** confirmed for AR9271 monitor mode
- [x] Backend unified on **port 8001**

### Phase 4 — Experiments & Paper (Pending)
- [ ] Run detection rate experiments
- [ ] Measure pipeline latency
- [ ] Snort/Suricata comparison
- [ ] ML model comparison
- [ ] CICIDS2017 validation
- [ ] IEEE-format paper

---

## Section E: System Architecture Summary

```
┌──────────────────────────────────────────────────────────────┐
│                    NTTH DEFENSE SYSTEM                       │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │ Main NIC    │  │ AR9271 USB   │  │ Network Scanner     │ │
│  │ wlp0s20f3   │  │ wlx...mon   │  │ (ping + port scan)  │ │
│  │ (promisc)   │  │ (monitor)    │  │ 28 ports × /24      │ │
│  └──────┬──────┘  └──────┬───────┘  └──────────┬──────────┘ │
│         │                │                      │            │
│         ▼                ▼                      ▼            │
│  ┌──────────────────────────────────────────────────────┐    │
│  │              EVENT BUS (pub/sub)                     │    │
│  │         device_seen → threat_detected →              │    │
│  │         enforcement_action → report_event            │    │
│  └──────────────────────────────────────────────────────┘    │
│         │                │                │                  │
│         ▼                ▼                ▼                  │
│  ┌────────────┐  ┌────────────┐  ┌────────────────────┐     │
│  │ Threat     │  │ Decision   │  │ Enforcement Agent  │     │
│  │ Agent      │  │ Agent      │  │ • nftables block   │     │
│  │ • IDS      │  │ • Risk→Act │  │ • Rate limit       │     │
│  │ • ML score │  │ • Protocol │  │ • Honeypot redirect │     │
│  │ • GeoIP    │  │   routing  │  │ • Auto-deploy HP   │     │
│  └────────────┘  └────────────┘  └────────────────────┘     │
│                                          │                   │
│                                          ▼                   │
│  ┌─────────────────────────────────────────────────────┐     │
│  │              HONEYPOT MESH (10+ ports)              │     │
│  │  FTP:21 │ Telnet:23 │ MySQL:3306 │ RDP:3389        │     │
│  │  VNC:5900 │ SMB:445 │ Redis:6379 │ MongoDB:27017   │     │
│  │  HTTP:8888 │ + dynamic ports on any attack          │     │
│  └─────────────────────────────────────────────────────┘     │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐     │
│  │         Flutter Dashboard (10 screens)               │     │
│  │  Dashboard │ Devices │ Threats │ Topology            │     │
│  │  Firewall │ Honeypot │ Wireless │ Packets            │     │
│  │  System │ Settings │ WebSocket real-time              │     │
│  └─────────────────────────────────────────────────────┘     │
│                                                              │
│  Port: 8001 │ DB: SQLite (ntth.db) │ Auth: JWT              │
└──────────────────────────────────────────────────────────────┘
```

---

## Section F: Known Configuration

| Setting | Value |
|---------|-------|
| Backend Port | 8001 |
| Subnet | 10.223.251.0/24 |
| Gateway | 10.223.251.124 (Vivo T4 5G hotspot) |
| Server IP | 10.223.251.241 |
| WiFi Band | 2.4 GHz (required for AR9271) |
| Main NIC | wlp0s20f3 (managed mode) |
| AR9271 | wlx24ec99bfe292 (monitor mode) |
| Database | SQLite at `backend/ntth.db` |
| Admin Login | admin / NtthAdmin2026 |
| Simulation | DISABLED |
| Scan Interval | 60 seconds |
