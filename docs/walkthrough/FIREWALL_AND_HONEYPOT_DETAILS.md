# Firewall & Honeypot Details

> Last updated: 2026-05-02

## Firewall (nftables)

### Manager: `app/firewall/nft_manager.py`

Three enforcement actions:

| Action | What it does | When triggered |
|--------|-------------|----------------|
| **Block** | Drop all packets from attacker IP | risk_score ≥ 0.95 |
| **Rate Limit** | Throttle attacker traffic | risk_score ≥ 0.35 |
| **Redirect** | DNAT attacker to honeypot port | risk_score ≥ 0.45 (TCP) |

### Rule Tracker: `app/firewall/rule_tracker.py`
- Deduplicates rules (no duplicate blocks for same IP)
- Persists rules to `firewall_rules` table
- Tracks active/expired state

### Rule Cleanup: `app/firewall/rule_cleanup.py`
- Auto-expires rules after TTL (default: 3600s = 1 hour)
- Runs as periodic scheduler task

---

## Honeypot System

### SSH Honeypot (Cowrie)
- **Port**: 30022
- **Type**: Docker container `ntth_cowrie`
- **Purpose**: Captures SSH commands from attackers
- **Log Watcher**: `cowrie_watcher.py` tails `cowrie.json` in real-time
- **Controller**: `cowrie_controller.py` — Docker API start/stop

### HTTP Honeypot
- **Port**: 8888
- **File**: `app/honeypot/http_honeypot.py`
- **Purpose**: Logs HTTP probes and credential attempts

### Multi-Protocol Honeypot (NEW)
- **File**: `app/honeypot/multi_honeypot.py`
- **Auto-deployed on startup**: 8 ports pre-armed before any attack arrives
- **Dynamic deployment**: Enforcement agent spawns new honeypots on any attacked port

| Port | Protocol | Banner/Lure |
|------|----------|-------------|
| 21 | FTP | ProFTPD 1.3.5 fake login |
| 23 | Telnet | Ubuntu 22.04 fake terminal |
| 80 | HTTP | Apache admin panel login |
| 443 | HTTPS | nginx secure portal |
| 445 | SMB | Connection logger |
| 3306 | MySQL | MySQL 5.7 handshake |
| 3389 | RDP | RDP negotiation |
| 5900 | VNC | RFB protocol |
| 6379 | Redis | Generic TCP |
| 8888 | HTTP-HP | Custom honeypot |
| 27017 | MongoDB | Generic TCP |
| *any* | Generic | TCP banner + connection log |

### How Honeypots Auto-Deploy

```
Packet → Threat Agent (risk = 0.85) → Decision Agent → Enforcement Agent
                                                              │
                                                ┌─────────────┤
                                                ▼             ▼
                                          nftables       deploy_honeypot(port)
                                          redirect       ← spawns TCP server
                                                           on attacked port
```

1. Attacker hits port 3389 (RDP)
2. IDS scores it as threat (risk > 0.45)
3. Decision agent routes to "honeypot" action
4. Enforcement agent:
   - Creates nftables redirect rule
   - Auto-deploys honeypot on port 3389
   - Logs interaction via event bus
5. Next connection on port 3389 hits the fake RDP server

### Honeypot Session Data

Each honeypot interaction captures:
- `attacker_ip` + `attacker_port`
- `honeypot_port` + `protocol`
- `connected_at` + `duration_seconds`
- `data_received` (up to 2000 chars)
- `commands` (for FTP/Telnet)
- `credentials_captured` (for HTTP POST)

All sessions published to event bus → Reporting Agent → DB + WebSocket → Flutter UI
