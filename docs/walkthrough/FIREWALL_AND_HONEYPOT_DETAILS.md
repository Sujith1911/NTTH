# Firewall And Honeypot Details

This file explains how firewall actions and honeypot session correlation work.

## 1. Main Files

- `backend/app/firewall/nft_manager.py`
- `backend/app/firewall/rule_tracker.py`
- `backend/app/api/routes_firewall.py`
- `backend/app/honeypot/session_logger.py`
- `backend/app/honeypot/cowrie_watcher.py`

## 2. Firewall Responsibilities

The firewall layer is responsible for:

- creating NTTH-owned nftables tables and chains
- adding block rules
- adding rate limit rules
- adding redirect rules
- tracking rule handles in the database
- deleting or flushing rules

## 3. nftables Tables And Chains

The current code creates:

- filter table: `inet ntth_filter`
- filter chain: `ntth_input`
- nat table: `ip ntth_nat`
- nat chain: `ntth_prerouting`

## 4. Rule Types

### Block

- drops all traffic from a source IP

### Rate Limit

- throttles noisy traffic from a source IP

### Redirect

- redirects a source flow to a honeypot port

## 5. Redirect Rule Shape

The redirect manager can include:

- source IP
- victim IP
- original victim port
- honeypot destination port

This is important because the attacker may choose any device from the protected pool.

## 6. Why Rule Tracking Matters

The system stores rule metadata in the DB so it can:

- avoid duplicate rules
- know which rules are active
- show rules in the UI
- expire or flush them later

## 7. Honeypot Session Correlation

### Problem

Cowrie may sometimes see a Docker-side or NAT-side IP instead of the true original attacker IP.

### Current approach

The system registers redirect context at enforcement time.

Later, when Cowrie logs are ingested, the session logger tries to correlate:

- observed attacker IP
- honeypot type
- recent redirect context

This can recover:

- original attacker IP
- victim IP
- victim port

when the context is unambiguous.

## 8. Cowrie Watcher Behavior

The Cowrie watcher:

- waits for the log file
- tails new lines
- reopens the file if it was replaced or rotated
- logs login and command events
- closes sessions when `cowrie.session.closed` appears

## 9. Current Firewall Limitations

In Windows plus Docker:

- the backend container may not control the true LAN path
- Docker NAT may mask attacker IPs
- real transparent redirect on production-like victim flows may not work

## 10. Firewall Upgrade Recommendations

### Deployment upgrades

- move enforcement to Ubuntu host
- avoid depending on Windows host Docker NAT for security path control
- prefer protected subnet or gateway deployment

### Code upgrades

- add protocol-aware redirect profiles
- add per-device deception policy
- add expiry and cleanup reporting
- add explicit audit trail for manual vs automatic rules
- expose nft runtime diagnostics in the UI

### Product upgrades

- allow users to mark protected devices
- allow per-device protected ports
- allow different honeypot types by service
