# NTTH — Progress Tracker & Remaining Work

> Last updated: 2026-04-21

---

## Section A: What's Built and Working (70%)

### Core Backend (100% ✅)

| # | Component | File | Status | Proof |
|---|-----------|------|--------|-------|
| 1 | FastAPI server | `app/main.py` | ✅ Done | Running on port 8000 in Docker |
| 2 | JWT auth (login/refresh) | `app/core/auth.py` | ✅ Done | admin/NtthAdmin2026 working |
| 3 | PostgreSQL database | Docker `ntth_postgres` | ✅ Done | 515+ threat events stored |
| 4 | SQLAlchemy models + CRUD | `app/database/` | ✅ Done | All tables created via Alembic |
| 5 | REST API (12 endpoints) | `app/api/` | ✅ Done | Verified via curl |
| 6 | WebSocket live updates | `app/websocket/` | ✅ Done | Real-time push to dashboard |
| 7 | Structured logging | `app/core/logger.py` | ✅ Done | JSON logs to file + console |
| 8 | Configuration system | `app/config.py` | ✅ Done | Pydantic settings + .env |

### Packet Capture & IDS (100% ✅)

| # | Component | File | Status | Details |
|---|-----------|------|--------|---------|
| 9 | Scapy packet sniffer | `app/monitor/packet_sniffer.py` | ✅ Done | AsyncSniffer on wlp0s20f3 |
| 10 | Feature extractor | `app/monitor/feature_extractor.py` | ✅ Done | 8 features: src_ip, dst_port, flags... |
| 11 | Device registry | `app/monitor/device_registry.py` | ✅ Done | Per-IP packet/SYN/port counts |
| 12 | Network scanner (ARP) | `app/monitor/network_scanner.py` | ✅ Done | LAN device discovery |
| 13 | Port scan detector | `app/ids/rule_engine.py` | ✅ Done | 4 unique ports in 15s window |
| 14 | SYN flood detector | `app/ids/rule_engine.py` | ✅ Done | 30 SYN/sec threshold |
| 15 | Brute force detector | `app/ids/rule_engine.py` | ✅ Done | 3 attempts in 120s to auth ports |
| 16 | Isolation Forest ML | `app/ids/anomaly_model.py` | ✅ Done | 200 trees, trains on 500 samples |
| 17 | Risk calculator | `app/ids/risk_calculator.py` | ✅ Done | 0.6×rule + 0.4×ml |
| 18 | GeoIP lookup | `app/geoip/geo_lookup.py` | ✅ Done | MaxMind GeoLite2 City + ASN |

### AI Agent Pipeline (100% ✅)

| # | Component | File | Status | Details |
|---|-----------|------|--------|---------|
| 19 | Event bus (pub/sub) | `app/core/event_bus.py` | ✅ Done | asyncio.Queue, 5000 capacity |
| 20 | Threat Agent | `app/agents/threat_agent.py` | ✅ Done | IDS + ML + GeoIP enrichment |
| 21 | Decision Agent | `app/agents/decision_agent.py` | ✅ Done | Risk→action, protocol-aware routing |
| 22 | Enforcement Agent | `app/agents/enforcement_agent.py` | ✅ Done | nftables + redirect context |
| 23 | Reporting Agent | `app/agents/reporting_agent.py` | ✅ Done | DB persist + WS broadcast |

### Firewall (100% ✅)

| # | Component | File | Status | Details |
|---|-----------|------|--------|---------|
| 24 | nftables manager | `app/firewall/nft_manager.py` | ✅ Done | block, rate_limit, redirect |
| 25 | Rule tracker | `app/firewall/rule_tracker.py` | ✅ Done | Deduplication + DB tracking |
| 26 | Rule cleanup | `app/firewall/rule_cleanup.py` | ✅ Done | Auto-expire after TTL |

### Honeypot (100% ✅)

| # | Component | File | Status | Details |
|---|-----------|------|--------|---------|
| 27 | Cowrie SSH honeypot | Docker `ntth_cowrie` | ✅ Done | Port 30022, captures commands |
| 28 | Cowrie log watcher | `app/honeypot/cowrie_watcher.py` | ✅ Done | Tails cowrie.json in real-time |
| 29 | Session logger | `app/honeypot/session_logger.py` | ✅ Done | DB + WS + GeoIP |
| 30 | HTTP honeypot | `app/honeypot/http_honeypot.py` | ✅ Done | Port 8888, logs probes |
| 31 | Cowrie controller | `app/honeypot/cowrie_controller.py` | ✅ Done | Docker API start/stop |

### Flutter Dashboard (100% ✅)

| # | Component | File | Status | Details |
|---|-----------|------|--------|---------|
| 32 | Login screen | `screens/login_screen.dart` | ✅ Done | JWT auth, server URL |
| 33 | Dashboard screen | `screens/dashboard_screen.dart` | ✅ Done | Overview cards |
| 34 | Threat Map | `screens/threat_map_screen.dart` | ✅ Done | LIVE/RECENT badges, risk chips |
| 35 | Firewall Rules | `screens/firewall_screen.dart` | ✅ Done | NEW/EXPIRED, Active/History |
| 36 | Honeypot Sessions | `screens/honeypot_screen.dart` | ✅ Done | Terminal command display |
| 37 | Network Topology | `screens/topology_screen.dart` | ✅ Done | ARP device list |
| 38 | WebSocket service | `core/websocket_service.dart` | ✅ Done | Auto-reconnect |
| 39 | Dark theme | `theme/app_theme.dart` | ✅ Done | Glassmorphism effects |

### Documentation (100% ✅)

| # | Document | Status |
|---|----------|--------|
| 40 | AI Agent Architecture (742 lines) | ✅ Done |
| 41 | README with diagrams | ✅ Done |
| 42 | System Overview | ✅ Done |
| 43 | Agentic AI Flow | ✅ Done |
| 44 | Packet Sniffing & Detection | ✅ Done |
| 45 | Firewall & Honeypot Details | ✅ Done |
| 46 | Frontend Screen by Screen | ✅ Done |
| 47 | Walkthrough Index | ✅ Done |

---

## Section B: What Needs To Be Done (30%)

### 🔴 CRITICAL (Must do — paper gets rejected without these)

| # | Task | Effort | Time | Priority | Addresses |
|---|------|--------|------|----------|-----------|
| 48 | Run detection rate experiments (50 runs × 4 attack types) | Medium | 2 days | P0 | Problem 2 |
| 49 | Measure end-to-end response latency T1→T4 (200 packets) | Medium | 1 day | P0 | Problem 2 |
| 50 | Install Snort + Suricata, run identical attack comparison | Medium | 2 days | P0 | Problem 1, 2 |
| 51 | Ablation study: grid search weights (0.0 to 1.0) + ROC curves | Medium | 1 day | P0 | Problem 4 |
| 52 | Multi-model comparison (RF, SVM, KNN, DT vs IF) on same data | Medium | 2 days | P0 | Problem 3 |
| 53 | Collect real-world dataset: 10,000+ packets (attack + normal) | Large | 3 days | P0 | Problem 2, 3 |
| 54 | Validate on CICIDS2017 benchmark (2.8M records) | Medium | 2 days | P0 | Problem 3 |
| 55 | Write explicit comparison with AARF, AETHER, LLM Honeypot papers | Small | 1 day | P0 | Gap 1 |
| 56 | Write the research paper (IEEE format) | Large | 7 days | P0 | All |

### 🟡 IMPORTANT (Strengthens the paper significantly)

| # | Task | Effort | Time | Priority | Addresses |
|---|------|--------|------|----------|-----------|
| 57 | Add Feedback Agent (threshold adaptation + model retraining) | Medium | 2 days | P1 | Problem 5 |
| 58 | Add 4 more features to ML (window_size, ttl, entropy, fin_flag) | Small | 1 day | P1 | Problem 3 |
| 59 | Implement AR9271 monitor mode capture | Medium | 2 days | P1 | Novelty |
| 60 | WiFi probe request tracking | Medium | 1 day | P1 | Novelty |
| 61 | Deauth attack detection | Small | 1 day | P1 | Novelty |
| 62 | Honeypot engagement metrics collection | Small | 1 day | P1 | Problem 2 |

### 🟢 NICE TO HAVE (Extra polish)

| # | Task | Effort | Time | Priority |
|---|------|--------|------|----------|
| 63 | Rogue AP / Evil Twin detection | Medium | 2 days | P2 |
| 64 | Device presence dashboard (AR9271) | Medium | 2 days | P2 |
| 65 | LaTeX formatting + IEEE template | Small | 1 day | P2 |
| 66 | GitHub repo cleanup for reproducibility | Small | 1 day | P2 |
| 67 | Generate ROC curve plots + confusion matrix visuals | Small | 1 day | P2 |

---

## Section C: Revised Progress

```
SYSTEM IMPLEMENTATION  ████████████████████  100%  (items 1-47)
EXPERIMENTS            ░░░░░░░░░░░░░░░░░░░░    0%  (items 48-56)
WIRELESS (AR9271)      ░░░░░░░░░░░░░░░░░░░░    0%  (items 59-61)
FEEDBACK AGENT         ░░░░░░░░░░░░░░░░░░░░    0%  (item 57)
PAPER WRITING          ████████████████░░░░   75%  (item 56 — structure complete, [RESULT] placeholders pending)
─────────────────────────────────────────────────
OVERALL                ████████████░░░░░░░░   55%
```

### To reach "Strong Accept" (8.5/10):

```
Must complete items: 48-56       → takes ~12 days
Should complete items: 57-61     → takes ~7 days
Paper writing: item 54           → takes ~7 days
────────────────────────────────────────────────
Total estimated: 3-4 weeks of focused work
```

---

## Section D: Week-by-Week Plan

### Week 1: Data Collection
- [ ] Collect 10,000+ real packets (7,500 normal + 2,500 attack)
- [ ] Run 50 port scan attacks, record detection results
- [ ] Run 50 brute force attacks (Hydra + manual), record results
- [ ] Run 30 SYN flood attacks (hping3), record results
- [ ] Run 50 HTTP probes, record results
- [ ] Run 100 normal traffic sessions (browsing, YouTube, transfers)
- [ ] Measure end-to-end latency T1→T4 for 200 attack packets
- [ ] Install Snort, run same attacks, record results
- [ ] Install Suricata, run same attacks, record results

### Week 2: ML + Comparison
- [ ] Add 4 new features to ML feature vector (10-dim total)
- [ ] Train RF, SVM, KNN, DT on same dataset
- [ ] Run ablation study (grid search weights + ROC curves)
- [ ] Build comparison table (Snort vs Suricata vs NTTH)
- [ ] Download + preprocess CICIDS2017 dataset
- [ ] Validate Isolation Forest on CICIDS2017
- [ ] Generate confusion matrices + ROC plots
- [ ] Write explicit differentiation vs AARF, AETHER, LLM Honeypot

### Week 3: Improvements + AR9271
- [x] Implement AR9271 monitor mode capture (wifi_sniffer.py)
- [x] Add probe request tracking (probe_tracker.py)
- [x] Add deauth detection (deauth_detector.py)
- [x] Add rogue AP detection (rogue_ap_detector.py)
- [x] Add channel hopping (channel_hopper.py)
- [x] Add wireless API endpoints (routes_wireless.py)
- [x] Integrate WiFi threats into AI agent pipeline
- [x] Add persistent attacker tracker (persistent_tracker.py) — MAC-based
- [x] Add multi-protocol honeypot framework (multi_honeypot.py)
- [x] Expand honeypot coverage to all attacked ports
- [x] Auto-detect network subnet (no hardcoded IPs)
- [x] Implement Feedback Agent (feedback_agent.py) — FP tracking + honeypot engagement
- [x] Collect honeypot engagement metrics (via feedback_agent)
- [x] Add Wireless screen to Flutter dashboard (wireless_screen.dart)
- [x] Add Wireless to nav rail + drawer (10th screen)
- [x] Convert docs to HTML (NTTH_COMPLETE_SYSTEM_GUIDE.html, AR9271_PROJECT_MASTER_PLAN.html)
- [x] Add Dashboard wireless stats + feedback cards (main dashboard)
- [x] Add WiFi badge to threat map cards (_isWifiThreat)
- [x] Create routes_tracker.py — 8 REST endpoints (attacker/honeypot/feedback)
- [x] Add Feedback + Wireless agents to /system/agents (8 agents total)
- [x] Build experiment automation framework (experiments/run_experiments.py)
  - [x] Deauth detection accuracy (30+ runs)
  - [x] Pipeline latency measurement (P50/P95/P99)
  - [x] IDS confusion matrix (TP/FP/TN/FN + F1)
  - [x] Honeypot deployment test (5 protocols)
  - [x] Persistent tracker reconnection test (5 steps)
- [x] Build auto_monitor.py — automatic AR9271 detection + monitor mode
- [x] Integrate auto-monitor into main.py startup (before WiFi sniffer)
- [x] Create Dockerfile for containerized deployment
- [x] Create docker-compose.yml with host network + USB passthrough
- [x] Create scripts/start_ntth.sh auto-start script
- [x] Add auto_teardown_monitor to shutdown sequence
- [x] Expose auto_monitor status via /wireless/status API

### Audit Fixes (Week 3.5)
- [x] Fix persistent tracker to actually persist to disk (JSON file)
- [x] Fix memory leak in decision_agent _RECENT_DECISIONS (TTL pruning)
- [x] Fix memory leak in rule_engine sliding windows (maxlen + stale key pruning)
- [x] Add login rate limiting (5 attempts / 5 minutes per IP → 429)
- [ ] Add basic pytest tests for rule_engine + risk_calculator
- [ ] Tighten CORS origins for production
- [ ] Run experiments with real AR9271 data

### Week 4: Paper Writing
- [ ] Write Abstract + Introduction
- [ ] Write System Architecture (with diagrams)
- [ ] Write Experimental Setup + Results
- [ ] Write Related Work + Comparison
- [ ] Write Conclusion
- [ ] Format in IEEE template
- [ ] Review with professor
