# NTTH Springer/IEEE Experiment Plan

This plan converts the project from a demo-only report into a measurable systems-security evaluation. Run every test only on devices you own and only on the isolated `NTTH-Secure` hotspot.

## 1. Claim to Evaluate

Use this precise research claim:

> NTTH is a low-cost, event-driven security gateway prototype that performs transparent risk scoring, honeypot-assisted evidence collection, and reversible forwarding-layer containment for protected Wi-Fi clients.

Avoid these claims unless later experiments prove them:

- Full ML-based IDS.
- Explainable AI.
- Enterprise-grade IDS accuracy.
- Production autonomous defense.
- Advanced attacker attribution or physical tracking.

## 2. Metrics to Collect

| Metric | Why It Matters | Source |
|---|---|---|
| Detection outcome | Shows which controlled attacks are detected | Threat events and research metrics |
| False positives | Shows whether benign users are harmed | Normal traffic experiment labels |
| Capture-to-enforcement latency | Supports the near-real-time response claim | Research metrics |
| CPU/RAM/load | Shows gateway overhead | Research metrics `/system` snapshot |
| Event-bus backlog/drops | Shows overload behavior | Research metrics |
| DB size and growth | Shows storage cost | Research metrics |
| Block effectiveness | Proves Wi-Fi stays connected but Internet stops | Dashboard and client command |
| Unblock correctness | Proves reversible containment | Firewall state and client command |

## 3. API Endpoints for Experiments

Authenticate as admin first, then use the JWT token.

Start a labeled experiment:

```bash
curl -s -X POST http://192.168.4.1:8001/api/v1/research/experiments/start \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"benign_browsing_10min","scenario":"normal traffic","notes":"phone browsing, video, app background traffic"}'
```

Stop the active experiment:

```bash
curl -s -X POST http://192.168.4.1:8001/api/v1/research/experiments/stop \
  -H "Authorization: Bearer $TOKEN"
```

View live metrics:

```bash
curl -s http://192.168.4.1:8001/api/v1/research/metrics \
  -H "Authorization: Bearer $TOKEN"
```

Export CSV for paper tables:

```bash
curl -o ntth_research_metrics.csv \
  "http://192.168.4.1:8001/api/v1/research/metrics/export.csv?limit=100000" \
  -H "Authorization: Bearer $TOKEN"
```

Export raw JSONL:

```bash
curl -o ntth_research_metrics.jsonl \
  "http://192.168.4.1:8001/api/v1/research/metrics/export.jsonl?limit=100000" \
  -H "Authorization: Bearer $TOKEN"
```

## 4. Required Test Matrix

| Experiment | Duration | Expected Paper Table |
|---|---:|---|
| Idle phone connected | 10 min | Baseline event rate and false alerts |
| Normal browsing | 10 min | False-positive count and max risk |
| Video streaming | 10 min | Throughput stress without false block |
| App updates/download | 10 min | High-volume benign traffic result |
| DNS-heavy browsing | 5 min | DNS false-positive check |
| SSH honeypot login | 3 sessions | Honeypot evidence capture table |
| HTTP honeypot form | 3 sessions | HTTP evidence capture table |
| Port scan | 3 runs | Detection and latency table |
| Ping flood / burst traffic | 3 runs | Detection/rate-limit table |
| Block/unblock | 3 runs | Containment correctness table |

## 5. Paper Tables to Generate

### Table A: Detection Outcome

| Scenario | Runs | Detected | Missed | Action | Notes |
|---|---:|---:|---:|---|---|
| Port scan | 3 | fill after test | fill after test | block/rate-limit | ports involved |
| SSH honeypot | 3 | fill after test | fill after test | log/block | commands captured |
| HTTP honeypot | 3 | fill after test | fill after test | log | form fields captured |

### Table B: False Positive Study

| Benign Scenario | Duration | Threat Events | Max Risk | Wrong Block? |
|---|---:|---:|---:|---|
| Idle phone | 10 min | fill | fill | Yes/No |
| Browsing | 10 min | fill | fill | Yes/No |
| Video | 10 min | fill | fill | Yes/No |

### Table C: Latency

| Scenario | Samples | Min ms | Avg ms | Max ms |
|---|---:|---:|---:|---:|
| Port scan to block | fill | fill | fill | fill |
| Honeypot event to report | fill | fill | fill | fill |

### Table D: Resource Utilization

| Scenario | Load 1m | Max RSS KB | Event Bus Backlog | Dropped Events | DB Size MB |
|---|---:|---:|---:|---:|---:|
| Idle | fill | fill | fill | fill | fill |
| Browsing | fill | fill | fill | fill | fill |
| Attack | fill | fill | fill | fill | fill |

## 6. Writing Rules After Experiments

Use these precise phrases:

- "event-driven modular pipeline"
- "transparent risk scoring"
- "rule-assisted anomaly scoring heuristic"
- "policy-driven automated response"
- "near-real-time live response"
- "lab-validated gateway prototype"

Avoid these phrases:

- "AI agent architecture"
- "explainable AI"
- "ML-based IDS accuracy"
- "production-ready autonomous defense"
- "untraceable tracking"

## 7. Acceptance Target for Main-Conference Submission

The paper becomes much stronger if the final measurements show:

- No wrong block in normal browsing/video/download tests.
- Clear detection of scan and honeypot interaction.
- Capture-to-enforcement latency reported with actual min/avg/max.
- Event bus dropped-events count near zero in normal lab conditions.
- Database growth documented per hour.
- Limitations explicitly stated for IPv6, VPN, fragmented packets, IP-only blocking, and small lab scale.
