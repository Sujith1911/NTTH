# NTTH — Professor Review Summary

## What We Are Building

**NTTH (No Time To Hack)** is an Adaptive AI-Driven Honeypot Firewall — a system that autonomously detects cyber attacks on a local network and responds in real-time without human intervention.

**In simple terms:** When someone attacks any device on our network, the system automatically detects it using AI, blocks or redirects the attacker to a fake server (honeypot), captures everything the attacker does, and shows it all live on a dashboard.

### Key Components

1. **Packet Sniffer** — captures all network traffic using Scapy
2. **IDS Rule Engine** — detects port scans, brute force, SYN floods using sliding-window signatures
3. **ML Anomaly Detector** — Isolation Forest model trained on baseline traffic to catch zero-day attacks
4. **4 AI Agents** — autonomous pipeline: Threat → Decision → Enforcement → Reporting
5. **Firewall** — Linux nftables kernel firewall that blocks, throttles, or redirects attackers
6. **SSH Honeypot (Cowrie)** — fake SSH server that captures attacker commands, credentials, file downloads
7. **HTTP Honeypot** — fake web server that logs attack probes
8. **AR9271 Wireless Monitor** — USB WiFi adapter in monitor mode for probe request tracking and deauth detection
9. **Flutter Dashboard** — real-time web + mobile UI with WebSocket live updates

### Risk Scoring Formula

```
risk = 0.6 × rule_score + 0.4 × ml_score
```

Actions: Allow (<0.15) → Log (0.15-0.25) → Rate Limit (0.25-0.40) → Honeypot (0.40-0.80) → Block (≥0.80)

---

## Current Status

| Component | Status | Notes |
|-----------|--------|-------|
| Backend (FastAPI) | ✅ Complete | Running in Docker on Ubuntu |
| Packet Sniffer (Scapy) | ✅ Complete | Captures real LAN traffic |
| IDS Rule Engine | ✅ Complete | Port scan, SYN flood, brute force detection |
| ML Anomaly Model | ✅ Complete | Isolation Forest, trains on 500 samples |
| 4 AI Agents | ✅ Complete | Autonomous pipeline via async event bus |
| nftables Firewall | ✅ Complete | Block, rate limit, redirect rules |
| Cowrie SSH Honeypot | ✅ Complete | Captures commands, credentials, duration |
| HTTP Honeypot | ✅ Complete | Captures attack probes |
| GeoIP Enrichment | ✅ Complete | Country, city, ASN, lat/lon |
| PostgreSQL Database | ✅ Complete | Threats, rules, sessions, devices stored |
| WebSocket Live Updates | ✅ Complete | Real-time push to dashboard |
| Flutter Dashboard (Web) | ✅ Complete | Threat map, firewall, honeypot, topology screens |
| Flutter Dashboard (Android) | ✅ Complete | Same UI compiled for Android |
| Device Discovery (ARP) | ✅ Complete | Scans and identifies LAN devices |
| AR9271 Monitor Mode | 🟡 Planned | WiFi probe capture, deauth detection |
| Wireless Feature Extractor | 🟡 Planned | Parse 802.11 frames |
| Rogue AP / Evil Twin Detection | 🟡 Planned | Beacon frame analysis |
| Research Paper | 🟡 In Progress | Framework complete, writing not started |
| Experiment Data Collection | 🟡 Not Started | Need to run attack scenarios and record metrics |

---

## Progress: 70% Complete

```
████████████████████░░░░░░░░░░  70%
```

| Area | Progress | Weight |
|------|----------|--------|
| Core System (backend + agents + firewall + honeypot) | 100% | 40% → 40% |
| Dashboard (Flutter UI) | 100% | 15% → 15% |
| AR9271 Wireless Monitoring | 0% | 15% → 0% |
| Experiment Data Collection | 0% | 15% → 0% |
| Research Paper Writing | 10% (framework only) | 15% → 1.5% |
| **Total** | | **~56.5%** |

### Honest Assessment: **~57% complete**

---

## What's Left

| Task | Effort | Time Estimate |
|------|--------|--------------|
| Implement AR9271 monitor mode capture | Medium | 2-3 days |
| Add WiFi probe request tracking to NTTH | Medium | 1-2 days |
| Add deauth / rogue AP detection rules | Small | 1 day |
| Run all attack experiments and collect data | Medium | 2-3 days |
| Write research paper (IEEE format) | Large | 5-7 days |
| Review and polish paper | Medium | 2-3 days |
| **Total remaining** | | **~13-19 days** |

---

## Paper Target

**Title:** "NTTH: An Adaptive AI-Driven Honeypot Firewall with Wireless Threat Detection Using Agentic Response Pipeline"

**Type:** Novel Research Paper (not methodology comparison)

**Target Venue:** IEEE Conference (ICACCS / ICCCNT / ICICCS level)

**Novelty:** No existing system combines wireless monitoring + hybrid AI scoring + autonomous multi-agent pipeline + kernel firewall + dynamic honeypot — all in one closed-loop system using commodity hardware.
