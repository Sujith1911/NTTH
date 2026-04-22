# NTTH × AR9271 — Master Integration Plan & Project Tracker

> **Last Updated:** 2026-04-21  
> **Hardware Status:** AR9271 Validated ✅  
> **Project Phase:** Wireless Integration (Phase 3 of 4)

---

## Part 1: AR9271 Hardware Validation Record

### Device Under Test

| Property | Value |
|----------|-------|
| Adapter | Atheros AR9271 (Wavenex) |
| USB ID | `0cf3:9271` |
| OS | Ubuntu Linux |
| Driver | `ath9k_htc` |
| Interface | `wlx24ec99bfe292` → `wlan0mon` |

### Validation Results — 2026-04-21

| # | Test | Command | Result | Evidence |
|---|------|---------|--------|----------|
| 1 | USB Detection | `lsusb` | ✅ PASS | `0cf3:9271 Qualcomm Atheros Communications AR9271 802.11n` |
| 2 | Driver Loaded | `sudo airmon-ng` | ✅ PASS | `phy1 wlx24ec99bfe292 ath9k_htc Qualcomm Atheros AR9271` |
| 3 | Monitor Mode | `sudo airmon-ng start wlx24ec99bfe292` | ✅ PASS | `monitor mode vif enabled on wlan0mon` |
| 4 | Packet Injection | `sudo aireplay-ng --test wlan0mon` | ✅ PASS | `Injection is working! Found 8 APs` |
| 5 | Passive Capture | `sudo airodump-ng wlan0mon` | ✅ PASS | Multiple APs, channels, BSSIDs, WPA2/CCMP |

> **Overall:** Adapter fully operational for wireless security lab use.

### Validated Toolchain

- Aircrack-ng suite (airmon-ng, aireplay-ng, airodump-ng)
- Wireshark (supported)
- Kali Linux (compatible)

### Constraints

- AR9271 is **2.4 GHz only** — no 5 GHz / 6 GHz support
- Packet injection may have limitations outside standard 2.4 GHz channels

---

## Part 2: Current Project Structure

```
NTTH/
├── backend/
│   ├── app/
│   │   ├── agents/                    # AI Agent Pipeline
│   │   │   ├── threat_agent.py        # Stage 1: IDS + ML scoring
│   │   │   ├── decision_agent.py      # Stage 2: Risk → action mapping
│   │   │   ├── enforcement_agent.py   # Stage 3: nftables + honeypot
│   │   │   └── reporting_agent.py     # Stage 4: DB + WebSocket
│   │   ├── api/                       # REST API (12 endpoints)
│   │   ├── core/                      # Event bus, auth, logger, scheduler
│   │   ├── database/                  # SQLAlchemy models, CRUD, migrations
│   │   ├── firewall/                  # nftables manager, rule tracker
│   │   ├── geoip/                     # MaxMind GeoIP lookup
│   │   ├── honeypot/                  # Cowrie watcher, HTTP honeypot
│   │   ├── ids/                       # Rule engine, Isolation Forest, risk calc
│   │   ├── monitor/                   # Packet sniffer, feature extractor
│   │   │   ├── packet_sniffer.py      # Scapy AsyncSniffer (wired)
│   │   │   ├── feature_extractor.py   # 6-dim → 10-dim feature vector
│   │   │   ├── device_registry.py     # Per-IP in-memory state
│   │   │   ├── device_sync.py         # DB sync
│   │   │   └── network_scanner.py     # ARP/ping LAN discovery
│   │   ├── websocket/                 # Live WebSocket broadcast
│   │   ├── config.py                  # Pydantic settings
│   │   └── main.py                    # FastAPI lifespan + app factory
│   ├── cowrie/                        # Cowrie config + logs
│   ├── docker-compose.yml
│   ├── Dockerfile
│   ├── requirements.txt
│   └── .env                           # Runtime configuration
├── flutter_app/
│   └── lib/
│       ├── screens/                   # 9 screens (dashboard, threat map, etc.)
│       ├── core/                      # Auth, WebSocket services
│       ├── models/                    # Dart data models
│       ├── theme/                     # Dark glassmorphism theme
│       └── widgets/                   # Reusable components
├── docs/                              # All documentation
├── scripts/                           # Automation scripts
├── Makefile                           # Developer commands
└── README.md
```

### What's Built (Items 1–47: 100%)

| Module | Components | Status |
|--------|-----------|--------|
| Backend Core | FastAPI, JWT auth, PostgreSQL, SQLAlchemy, WebSocket, logging | ✅ |
| Packet Capture | Scapy sniffer, feature extractor, device registry, ARP scanner | ✅ |
| IDS Engine | Port scan, SYN flood, brute force detectors + Isolation Forest ML | ✅ |
| AI Agents | Threat → Decision → Enforcement → Reporting pipeline | ✅ |
| Firewall | nftables block/rate_limit/redirect, rule tracker, auto-cleanup | ✅ |
| Honeypot | Cowrie SSH (Docker), HTTP honeypot, log watcher, session logger | ✅ |
| Dashboard | Flutter: 9 screens, WebSocket, dark theme, glassmorphism | ✅ |
| Documentation | Architecture docs, walkthroughs, research paper draft | ✅ |

---

## Part 3: AR9271 Integration — What We're Building

### New Module: `backend/app/wireless/`

```
backend/app/wireless/
├── __init__.py
├── wifi_sniffer.py           # Monitor mode 802.11 frame capture
├── wifi_feature_extractor.py # Extract probe/deauth/beacon features
├── probe_tracker.py          # Track device presence via probe requests
├── deauth_detector.py        # Detect deauthentication attacks
├── rogue_ap_detector.py      # Detect rogue/evil twin APs
├── channel_hopper.py         # Background channel hopping (1-13)
└── wifi_config.py            # AR9271-specific settings
```

### AR9271 Features We Will Use

| # | Capability | How We Use It | Event Bus Topic |
|---|-----------|---------------|-----------------|
| 1 | **Monitor Mode** | Capture raw 802.11 frames passively | — |
| 2 | **Probe Request Capture** | Track device MAC, SSID history, RSSI | `wifi_probe_seen` |
| 3 | **Deauth Detection** | Count deauth frames/sec per BSSID | `wifi_threat_detected` |
| 4 | **Beacon Capture** | Build AP whitelist, detect rogues | `wifi_threat_detected` |
| 5 | **Channel Hopping** | Sweep channels 1–13 for full coverage | — |
| 6 | **Packet Injection** | Future: active rogue AP countermeasures | — |

### How It Integrates with Existing Pipeline

```
                        ┌──────────────────────────────────────┐
                        │  EXISTING WIRED PIPELINE             │
  Scapy Sniffer ───────►│  device_seen → threat_detected →     │
  (wlp0s20f3)           │  enforcement_action → report_event   │
                        └──────────────────────────────────────┘
                                         │
                        ┌────────────────┴─────────────────────┐
                        │  NEW WIRELESS PIPELINE               │
  AR9271 Sniffer ──────►│  wifi_probe_seen → probe_tracker     │
  (wlan0mon)            │  wifi_threat_detected → threat_agent │──► Same enforcement
                        │  wifi_rogue_ap → decision_agent      │    + reporting
                        └──────────────────────────────────────┘
```

**Key design:** WiFi threats feed into the *same* Decision → Enforcement → Reporting pipeline. No duplicate agents needed.

---

## Part 4: Implementation Plan (4 Phases)

### Phase 1: Wireless Capture Foundation (3 days)

**Goal:** Get raw 802.11 frames flowing through the event bus.

| Task | File | Details |
|------|------|---------|
| 1.1 | `wireless/wifi_config.py` | Add config: `WIFI_INTERFACE`, `WIFI_ENABLED`, `WIFI_CHANNELS`, `AP_WHITELIST` |
| 1.2 | `wireless/channel_hopper.py` | Background asyncio task hopping channels 1–13 every 0.3s via `iw dev wlan0mon set channel N` |
| 1.3 | `wireless/wifi_sniffer.py` | Scapy AsyncSniffer on `wlan0mon` with filter for Dot11 frames, publish to event bus |
| 1.4 | `wireless/wifi_feature_extractor.py` | Parse Dot11 ProbeReq, Dot11Deauth, Dot11Beacon → feature dicts |
| 1.5 | `config.py` | Add `wifi_interface`, `wifi_enabled`, `ap_whitelist_ssids`, `deauth_threshold` settings |
| 1.6 | `main.py` | Add `wifi_sniffer_task` to lifespan startup/shutdown |
| 1.7 | `.env` | Add `WIFI_INTERFACE=wlan0mon`, `WIFI_ENABLED=true` |

**Validation:** Run backend, verify `wifi_sniffer.started` in logs, see `wifi_probe_seen` events.

### Phase 2: WiFi Threat Detection (4 days)

**Goal:** Detect wireless threats and feed them into the AI agent pipeline.

| Task | File | Details |
|------|------|---------|
| 2.1 | `wireless/probe_tracker.py` | In-memory registry: MAC → {SSIDs, RSSI history, first/last seen, probe count} |
| 2.2 | `wireless/deauth_detector.py` | Sliding window: >10 deauth frames/sec targeting same BSSID → `wifi_threat_detected` with `threat_type: deauth_attack` |
| 2.3 | `wireless/rogue_ap_detector.py` | Compare beacon SSIDs against whitelist. Same SSID + different BSSID → `wifi_threat_detected` with `threat_type: rogue_ap` |
| 2.4 | `agents/threat_agent.py` | Subscribe to `wifi_threat_detected`, score deauth/rogue threats (rule_score=1.0) |
| 2.5 | `ids/rule_engine.py` | Add `_detect_deauth_flood()` and `_detect_rogue_ap()` to the evaluate pipeline |
| 2.6 | `database/models.py` | Add `wifi_events` table: id, mac, ssid, rssi, frame_type, channel, timestamp |
| 2.7 | `api/routes_wireless.py` | New endpoints: `GET /wireless/probes`, `GET /wireless/threats`, `GET /wireless/devices` |

**Validation:** Trigger deauth with `aireplay-ng --deauth 20 -a <BSSID> wlan0mon`, verify detection.

### Phase 3: Dashboard Integration (3 days)

**Goal:** Visualize wireless data in the Flutter dashboard.

| Task | File | Details |
|------|------|---------|
| 3.1 | `wireless_screen.dart` | New screen: device presence list, probe history, RSSI signal bars |
| 3.2 | `threat_map_screen.dart` | Add WiFi threat badges (DEAUTH, ROGUE_AP) alongside existing types |
| 3.3 | `dashboard_screen.dart` | Add wireless stats card: devices detected, active threats, adapter status |
| 3.4 | `topology_screen.dart` | Overlay WiFi-discovered devices with ARP-discovered devices |
| 3.5 | WebSocket | Broadcast `wifi_probe_seen` and `wifi_threat_detected` events |
| 3.6 | API | `GET /api/v1/wireless/status` — adapter state, channel, capture stats |

### Phase 4: Experimental Validation (4 days)

**Goal:** Generate data for research paper sections.

| Task | Details |
|------|---------|
| 4.1 | Capture 1000+ probe requests from lab devices, measure detection accuracy |
| 4.2 | Run 30 deauth attack scenarios, record detection rate and response latency |
| 4.3 | Deploy rogue AP (hostapd), verify rogue AP detection |
| 4.4 | Measure WiFi pipeline latency: frame capture → threat_detected → enforcement |
| 4.5 | Generate confusion matrix for WiFi threat classification |
| 4.6 | Write paper Section V.D with real experimental results |
| 4.7 | Update Table I comparison — NTTH is the only system with wireless monitoring |

---

## Part 5: Progress Tracker

```
SYSTEM IMPLEMENTATION  ████████████████████  100%  (items 1–47)
PAPER WRITING          ████████████████░░░░   75%  (draft complete, results pending)
AR9271 VALIDATION      ████████████████████  100%  (all 5 tests passed)
WIRELESS PHASE 1       ░░░░░░░░░░░░░░░░░░░░    0%  (capture foundation)
WIRELESS PHASE 2       ░░░░░░░░░░░░░░░░░░░░    0%  (threat detection)
WIRELESS PHASE 3       ░░░░░░░░░░░░░░░░░░░░    0%  (dashboard)
WIRELESS PHASE 4       ░░░░░░░░░░░░░░░░░░░░    0%  (experiments)
EXPERIMENTS (WIRED)    ░░░░░░░░░░░░░░░░░░░░    0%  (items 48–56)
FEEDBACK AGENT         ░░░░░░░░░░░░░░░░░░░░    0%  (item 57)
─────────────────────────────────────────────────
OVERALL                ████████████░░░░░░░░   58%
```

### Milestone Checklist

#### ✅ Completed
- [x] AR9271 USB detection (lsusb)
- [x] ath9k_htc driver loaded (airmon-ng)
- [x] Monitor mode enabled (wlan0mon)
- [x] Packet injection verified (aireplay-ng)
- [x] Passive capture verified (airodump-ng)
- [x] Full wired IDS pipeline operational
- [x] All 4 AI agents working
- [x] Flutter dashboard with 9 screens
- [x] Research paper draft (structure + placeholders)

#### 🔲 Phase 1: Capture Foundation
- [ ] `wifi_config.py` — settings for AR9271
- [ ] `channel_hopper.py` — channel sweep 1–13
- [ ] `wifi_sniffer.py` — Dot11 frame capture
- [ ] `wifi_feature_extractor.py` — frame parsing
- [ ] Config + .env updates
- [ ] Lifespan integration in `main.py`
- [ ] Verify events flowing in logs

#### 🔲 Phase 2: Threat Detection
- [ ] `probe_tracker.py` — device presence registry
- [ ] `deauth_detector.py` — sliding window detection
- [ ] `rogue_ap_detector.py` — whitelist comparison
- [ ] Threat agent WiFi subscription
- [ ] Rule engine WiFi detectors
- [ ] `wifi_events` DB table + migration
- [ ] Wireless API endpoints

#### 🔲 Phase 3: Dashboard
- [ ] `wireless_screen.dart` — new Flutter screen
- [ ] Threat map WiFi badges
- [ ] Dashboard wireless stats card
- [ ] Topology WiFi device overlay
- [ ] WebSocket WiFi event broadcast
- [ ] Wireless status API

#### 🔲 Phase 4: Experiments
- [ ] Probe request capture dataset (1000+)
- [ ] Deauth detection experiments (30 runs)
- [ ] Rogue AP detection test
- [ ] WiFi pipeline latency measurement
- [ ] Confusion matrix generation
- [ ] Paper Section V.D with real data
- [ ] Updated comparison table

---

## Part 6: Targeted Goals

### Academic Goals

| Goal | Metric | Target |
|------|--------|--------|
| WiFi detection rate (deauth) | True positive rate | ≥ 95% |
| WiFi detection rate (rogue AP) | True positive rate | ≥ 90% |
| WiFi false positive rate | False alarm rate | ≤ 5% |
| WiFi pipeline latency | Frame → threat_detected | ≤ 200 ms |
| Probe tracking accuracy | Unique MACs identified | ≥ 98% |
| Paper novelty claim | "Only system with wireless monitoring" | Validated via Table I |

### System Goals

| Goal | Description |
|------|-------------|
| Dual-interface monitoring | Wired (wlp0s20f3) + Wireless (wlan0mon) simultaneously |
| Unified threat pipeline | WiFi threats use same Decision → Enforcement → Reporting agents |
| Real-time dashboard | WiFi devices and threats visible within 1 second |
| Zero-config deployment | AR9271 auto-detected and configured on startup |
| Graceful degradation | System runs normally if AR9271 is unplugged |

### Research Paper Impact

| Section | What AR9271 Adds |
|---------|-----------------|
| Abstract | "convergent wired and wireless threat detection" |
| Contribution #4 | Wireless monitoring via commodity $10 USB adapter |
| Table I | Only system with wireless monitoring column = "Yes" |
| Section V.D | Full wireless module implementation details |
| Section VI | WiFi detection experiments + latency measurements |
| Section VII | 2.4 GHz limitation acknowledged, 5 GHz future work |

---

## Part 7: How to Run Everything

### Prerequisites
```bash
# 1. System packages
sudo apt update && sudo apt install -y aircrack-ng iw wireless-tools docker.io docker-compose python3-pip

# 2. Python dependencies
cd /home/ubuntu/NTTH/backend
pip install -r requirements.txt

# 3. AR9271 setup (one-time)
sudo airmon-ng check kill              # Kill interfering processes
sudo airmon-ng start wlx24ec99bfe292   # Enable monitor mode → wlan0mon
```

### Running the System

#### Option A: Development Mode (recommended for now)
```bash
# Terminal 1: Start backend
cd /home/ubuntu/NTTH/backend
sudo uvicorn app.main:app --reload --port 8000 --log-level info

# Terminal 2: Verify AR9271 is active
sudo airmon-ng   # Should show wlan0mon with ath9k_htc
```

#### Option B: Docker Production Mode
```bash
cd /home/ubuntu/NTTH/backend
# Update .env with WIFI_INTERFACE=wlan0mon, WIFI_ENABLED=true
docker compose up -d
```

> [!IMPORTANT]
> The backend container needs `--privileged` or `cap_add: [NET_ADMIN, NET_RAW]` plus access to the USB device for AR9271 monitor mode inside Docker.

#### Option C: Make Targets
```bash
make dev            # Start backend dev mode
make prod           # Docker Compose production
make test-all       # Run all tests
make simulate       # Inject simulated attacks
```

### Verifying the System

```bash
# 1. Health check
curl http://localhost:8000/api/v1/system/health

# 2. Login + get token
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"NtthAdmin2026"}' | jq -r .access_token)

# 3. Check devices
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/devices

# 4. Check threats
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/threats

# 5. After wireless module: Check WiFi devices
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/wireless/devices
```

### Attack Testing with AR9271

```bash
# Deauth attack test (from second terminal)
sudo aireplay-ng --deauth 20 -a <TARGET_BSSID> wlan0mon

# Passive monitoring verification
sudo airodump-ng wlan0mon --write /tmp/ntth_capture --output-format pcap

# Rogue AP test (requires hostapd)
sudo hostapd /tmp/rogue_ap.conf   # Config with same SSID as target network
```

### Flutter Dashboard
```bash
# Web build (for serving from backend)
cd /home/ubuntu/NTTH/flutter_app
flutter build web
# Dashboard auto-served at http://localhost:8000/

# Desktop (development)
flutter run -d linux
```

---

## Part 8: Week-by-Week Schedule

### Week 1: Wireless Foundation (Phase 1 + 2 start)
- [ ] Implement `wireless/` module (config, sniffer, channel hopper)
- [ ] Implement feature extractor for Dot11 frames
- [ ] Implement probe tracker
- [ ] Test: verify probe request events flowing

### Week 2: Wireless Threats + API (Phase 2 complete)
- [ ] Implement deauth detector
- [ ] Implement rogue AP detector
- [ ] Add WiFi event subscriptions to threat agent
- [ ] Create wireless API endpoints
- [ ] DB migration for `wifi_events` table
- [ ] Test: trigger deauth, verify detection pipeline

### Week 3: Dashboard + Experiments (Phase 3 + 4 start)
- [ ] Build `wireless_screen.dart` in Flutter
- [ ] Add WiFi badges to threat map
- [ ] Run deauth detection experiments (30 runs)
- [ ] Capture probe request dataset
- [ ] Start rogue AP detection tests

### Week 4: Paper + Polish (Phase 4 complete)
- [ ] Measure WiFi pipeline latency (200 frames)
- [ ] Generate confusion matrices
- [ ] Write paper Section V.D with real results
- [ ] Update all comparison tables
- [ ] Run wired experiments (items 48–56)
- [ ] Final paper revision

---

## Part 9: Configuration Reference

### New `.env` Variables (after integration)

```env
# ── Existing (unchanged) ──
NETWORK_INTERFACE=wlp0s20f3
GATEWAY_IP=10.223.251.124
SCAN_SUBNET=10.223.251.0/24
SERVER_DISPLAY_IP=10.223.251.241

# ── New: AR9271 Wireless ──
WIFI_ENABLED=true
WIFI_INTERFACE=wlan0mon
WIFI_CHANNELS=1,2,3,4,5,6,7,8,9,10,11,12,13
WIFI_HOP_INTERVAL=0.3
DEAUTH_THRESHOLD=10
DEAUTH_WINDOW_SECONDS=1
AP_WHITELIST_SSIDS=MyNetwork,MyNetwork_5G
ROGUE_AP_DETECTION=true
PROBE_TRACKING=true
```

### New Event Bus Topics

| Topic | Publisher | Subscriber | Payload |
|-------|----------|------------|---------|
| `wifi_probe_seen` | wifi_sniffer | probe_tracker | `{mac, ssid, rssi, channel, timestamp}` |
| `wifi_threat_detected` | deauth/rogue detectors | threat_agent | `{threat_type, mac, bssid, details}` |
| `wifi_device_update` | probe_tracker | reporting_agent | `{mac, ssid_list, signal, first/last_seen}` |

### New API Endpoints

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /api/v1/wireless/status` | User | AR9271 adapter state, channel, stats |
| `GET /api/v1/wireless/devices` | User | Tracked WiFi devices (probe-based) |
| `GET /api/v1/wireless/probes` | User | Recent probe request log |
| `GET /api/v1/wireless/threats` | User | WiFi-specific threat events |
| `POST /api/v1/wireless/whitelist` | Admin | Update AP SSID whitelist |

---

## Part 10: Risk & Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| AR9271 disconnected during runtime | WiFi monitoring stops | Graceful degradation — wired pipeline unaffected |
| Channel hopping misses frames | Reduced detection coverage | Configurable hop interval, lock-channel option |
| MAC randomization defeats tracking | Probe tracker inaccurate | Timing + IE fingerprinting per Vanhoef [21] |
| Docker can't access USB device | No WiFi in container | Run backend on host, or `--device /dev/bus/usb` |
| 5 GHz networks invisible | Incomplete wireless coverage | Documented limitation; future MT7612U adapter |
| High deauth false positives | Alert fatigue | Tunable threshold (default 10/sec), sustained pattern |
