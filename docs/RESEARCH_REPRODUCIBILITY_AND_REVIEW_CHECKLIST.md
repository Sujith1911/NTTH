# NTTH Research Reproducibility and Reviewer Checklist

Use this checklist before submitting to a Springer/IEEE main conference or demo track.

## 1. Claim Precision

Use:

- Lab-validated gateway prototype.
- Event-driven modular pipeline.
- Transparent risk scoring.
- Rule-assisted anomaly scoring heuristic.
- Policy-driven automated response.
- Reversible forwarding-layer containment.

Avoid:

- AI agent architecture.
- Explainable AI.
- ML-based IDS accuracy.
- Production-ready autonomous defense.
- Physical attacker tracking.
- Enterprise-grade firewall.

## 2. Minimum Measured Results Required

The paper should not be submitted to a main conference until these are filled with real values:

| Required Result | Status | Source |
|---|---|---|
| Detection outcomes for scan/honeypot/burst tests | Pending live experiment | `/api/v1/research/metrics/export.csv` |
| False-positive study for benign phone usage | Pending live experiment | experiment labels + threat events |
| Capture-to-enforcement latency | Instrumented, pending live experiment | research metrics JSONL |
| CPU/RAM/load during idle/browsing/attack | Instrumented, pending live experiment | `/api/v1/research/metrics` |
| Event bus backlog and dropped events | Instrumented, pending live experiment | event bus counters |
| DB growth per hour | Instrumented, pending live experiment | DB size snapshots |
| Block/unblock correctness | Pending repeated live test | firewall state + client curl |

## 3. Hardware Reproducibility Fields

Fill these before submission:

```bash
lscpu
free -h
lsb_release -a
uname -a
ip addr
iw dev
lsusb
python3 --version
docker --version
nft --version
```

Required table fields:

| Field | Value |
|---|---|
| CPU | 12th Gen Intel Core i7-1255U, 12 logical CPUs |
| RAM | 15 GiB RAM, 4 GiB swap |
| Ubuntu version | Ubuntu 24.04.4 LTS |
| Kernel version | Linux 6.17.0-22-generic |
| Wi-Fi adapter model/chipset | Qualcomm Atheros AR9271 802.11n USB (`0cf3:9271`) |
| Protected interface | `wlx24ec99bfe292` in current gateway config |
| Gateway IP | `192.168.4.1` |
| Protected subnet | `192.168.4.0/24` |
| Dashboard URL | `http://192.168.4.1:8001` |
| Cowrie port | `30022` |
| HTTP honeypot port | `8888` |
| Python | 3.12.3 in backend virtualenv |
| Docker | 29.4.1 |
| nftables | 1.0.9 |
| hostapd | 2.10 |

## 4. Critical Configuration Values

| Setting | Current Value | Paper Interpretation |
|---|---:|---|
| `RISK_BLOCK_THRESHOLD` | `0.75` | Hand-tuned lab containment threshold |
| `risk_rate_limit_threshold` | `0.60` | Suspicious/noisy behavior threshold |
| `port_scan_unique_ports` | `8` | Needs sensitivity discussion |
| `port_scan_window_seconds` | `10` | Needs sensitivity discussion |
| `syn_flood_per_second` | `80` | Lab heuristic |
| `brute_force_attempts` | `5` | Lab heuristic |
| `event_bus_queue_size` | `5000` | Backpressure limit |
| `packet_retention_days` | `7` | Storage-control policy |

## 5. Security and Ethics Requirements

The paper must state:

- Tests are performed only on owned devices.
- Users must consent before joining the monitored hotspot.
- HTTP form capture is for controlled demonstrations only.
- HTTPS content is not decrypted.
- TLS metadata may expose browsing destinations and must be handled as sensitive data.
- Dashboard credentials must be changed before any public deployment.
- The management interface should not be exposed to untrusted networks.
- Covert location tracking is outside the project scope and is not supported.

Current implementation notes:

- REST API routes use JWT bearer authentication.
- Live WebSocket updates require a JWT query token at `/ws/live?token=...` and close unauthenticated clients.
- Research export endpoints require an admin account.
- The dashboard still runs on the protected gateway address, so demo users should connect only owned/consenting devices.
- Long-term hardening should split privileged capture/firewall operations from the web API process.

## 6. Reviewer Risk Areas and Required Wording

| Reviewer Concern | Required Paper Handling |
|---|---|
| Integration is engineering, not science | Frame as applied systems architecture with measurable closed-loop behavior |
| Too few detectors | Admit detector scope and evaluate only claimed scenarios |
| ML overclaim | Use "heuristic anomaly scoring"; make trained ML future work |
| Agent overclaim | Use "event-driven modular pipeline" |
| Explainability overclaim | Use "transparent scoring" |
| IP-only blocking | List as limitation and future MAC-aware work |
| Local LAN abuse after block | State forward-chain block stops Internet only; local isolation is future work |
| No false positives | Run benign experiment matrix |
| No latency | Use new research metrics |
| Security of NTTH itself | Discuss dashboard hardening and privilege separation |

## 7. Artifact Files

| File | Purpose |
|---|---|
| `docs/SPRINGER_NTTH_RESEARCH_PAPER.md` | Springer-style paper draft |
| `docs/SPRINGER_IEEE_EXPERIMENT_PLAN.md` | Live experiment protocol |
| `backend/app/research/metrics.py` | Metrics recorder |
| `backend/app/api/routes_research.py` | Research API endpoints |
| `scripts/analyze_research_metrics.py` | Converts JSONL to markdown tables |

## 8. Final Submission Rule

Do not invent measurements. If live experiments are not run, submit as:

- final-year project report,
- demo paper,
- poster paper,
- workshop prototype paper.

Submit as a main conference paper only after the required measurement tables are populated from live experiments.
