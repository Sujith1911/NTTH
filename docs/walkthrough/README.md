# NTTH Documentation — Walkthrough Index

> Last updated: 2026-05-02

## Quick Start

1. Plug in AR9271 USB adapter
2. Switch WiFi to **2.4 GHz** band
3. Run: `bash start.sh`
4. Open: http://localhost:8001
5. Login: `admin` / `NtthAdmin2026`

## Document Guide

### Architecture & Design
| Document | Description |
|----------|-------------|
| [System Overview](SYSTEM_OVERVIEW.md) | Full architecture, components, and design decisions |
| [AI Agent Architecture](../AI_AGENT_ARCHITECTURE.md) | 6-agent pipeline: Threat → Decision → Enforcement → Reporting → Feedback |
| [Agentic AI Flow](AGENTIC_AI_AND_RESPONSE_FLOW.md) | Event bus pub/sub flow and threat response logic |

### Backend Deep Dives
| Document | Description |
|----------|-------------|
| [Packet Sniffing & Detection](PACKET_SNIFFING_AND_ATTACK_DETECTION.md) | Scapy sniffer, IDS rules, ML anomaly model |
| [Firewall & Honeypot](FIREWALL_AND_HONEYPOT_DETAILS.md) | nftables + Cowrie + multi-protocol honeypots |
| [DB Schema](DB_SCHEMA_EXPLANATION.md) | Tables: devices, threats, packets, firewall rules |
| [API Walkthrough](API_BY_API_WALKTHROUGH.md) | All 15+ REST endpoints |

### Frontend
| Document | Description |
|----------|-------------|
| [Screen by Screen](FRONTEND_SCREEN_BY_SCREEN.md) | All 10 Flutter dashboard screens |
| [Frontend-Backend Flow](FRONTEND_BACKEND_FLOW.md) | REST + WebSocket communication |

### Deployment & Operations
| Document | Description |
|----------|-------------|
| [Physical Ubuntu Setup](PHYSICAL_UBUNTU_SETUP.md) | AR9271 + monitor mode + network config |
| [Deployment & Demo Guide](DEPLOYMENT_AND_DEMO_GUIDE.md) | Full deployment walkthrough |
| [Local Run Guide](LOCAL_RUN_GUIDE.md) | Quick local development setup |
| [Docker Setup](DOCKER_SETUP.md) | Containerized deployment |
| [Attack Test Runbook](../KALI_ATTACK_TEST_RUNBOOK.md) | Step-by-step attack simulation commands |

### Project Status
| Document | Description |
|----------|-------------|
| [Progress Tracker](../PROGRESS_TRACKER.md) | 90% complete — 67 items done, 8 remaining |
| [AR9271 Master Plan](../AR9271_PROJECT_MASTER_PLAN.md) | Wireless monitoring integration plan |

## System Components (67 items)

```
Core Backend ........... 9 items  ✅ 100%
Packet Capture & IDS ... 11 items ✅ 100%
AI Agent Pipeline ...... 6 items  ✅ 100%
Firewall ............... 3 items  ✅ 100%
Honeypot System ........ 8 items  ✅ 100%
Wireless / AR9271 ...... 8 items  ✅ 100%
Flutter Dashboard ...... 13 items ✅ 100%
Infrastructure ......... 5 items  ✅ 100%
Data Integrity ......... 4 items  ✅ 100%
────────────────────────────────────────
TOTAL                    67 items ✅ 100%
```

## What's Left (Experiments & Paper)
- Detection rate experiments (50 runs × 4 attack types)
- Pipeline latency measurement
- Snort/Suricata comparison
- ML model comparison + CICIDS2017 validation
- IEEE-format research paper
