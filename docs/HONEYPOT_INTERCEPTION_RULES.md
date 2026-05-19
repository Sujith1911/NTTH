# NTTH Honeypot Interception Rules

This document defines the first production-safe interception policy for SSH and HTTP service attacks inside the protected `NTTH-Secure` network.

## Current Assumptions

- Gateway mode is active.
- `hostapd` is running as AP on `wlx24ec99bfe292`.
- `ap_isolate=1` is enabled, preventing direct Wi-Fi client-to-client Layer-2 communication.
- Suspicious client traffic traverses the NTTH gateway enforcement path.
- The target devices and attacking device are owned/authorized lab devices.

## Policy

NTTH should not redirect every first connection to SSH/HTTP, because normal users may legitimately connect to services. Instead:

1. Observe initial traffic.
2. Score the source using rule-assisted risk scoring.
3. When the source reaches suspicious/rate-limit risk level, intercept protected service traffic.
4. Redirect the suspicious source to NTTH honeypots.
5. Keep rule records so Clear Risk & Unblock can remove the redirect.

## SSH Rule

When a suspicious source attacks any protected device on TCP port `22`:

```text
attacker_ip -> victim_ip:22
```

NTTH creates a targeted redirect:

```text
ip saddr <attacker_ip> ip daddr <victim_ip> tcp dport 22 redirect to :30022
```

Result:

```text
attacker_ip -> victim_ip:22 -> NTTH Cowrie honeypot on :30022
```

Cowrie can then capture usernames, password attempts, and commands.

## HTTP Rule

When a suspicious source attacks any protected device on TCP port `80` or `8080`:

```text
attacker_ip -> victim_ip:80
attacker_ip -> victim_ip:8080
```

NTTH creates a targeted redirect:

```text
ip saddr <attacker_ip> ip daddr <victim_ip> tcp dport 80 redirect to :8888
ip saddr <attacker_ip> ip daddr <victim_ip> tcp dport 8080 redirect to :8888
```

Result:

```text
attacker_ip -> victim HTTP service -> NTTH HTTP honeypot on :8888
```

The HTTP honeypot can capture plain HTTP paths, headers, form fields, and request timing.

## Direct Honeypot Ports

Traffic already targeting NTTH honeypot ports is not redirected again:

```text
30022 -> Cowrie SSH honeypot
8888  -> HTTP honeypot
```

## Current Scope

Implemented first:

- SSH `22 -> 30022`
- HTTP `80/8080 -> 8888`

Not yet implemented in this first rule set:

- MySQL `3306`
- PostgreSQL `5432`
- SMB `445`
- RDP `3389`
- VNC `5900`

These can be added after SSH/HTTP are verified because SQL/SMB/RDP need better protocol-specific decoys to avoid overstating honeypot realism.

## Scan Detection Coverage Before Interception

NTTH now raises suspicious/rate-limit risk for more than one fixed demo command. The rule engine watches for:

- TCP/UDP port diversity, including default `nmap`, `nmap -A`, `nmap -sT`, and many UDP scan patterns.
- ARP discovery sweeps such as `nmap -sn -PR 192.168.4.0/24` and `arp-scan` style behavior.
- ICMP or multi-host discovery sweeps across many protected IPs.
- Stealth/OS-detection style TCP probes such as NULL/FIN/XMAS-like flag patterns.
- SYN floods and repeated authentication-service hits.

Default suspicious scan thresholds:

```text
8 unique destination ports in 10 seconds
8 unique discovered hosts in 10 seconds
8 unique ARP targets in 10 seconds
3 stealth TCP flag probes in 10 seconds
```

When these rules produce risk at or above the rate-limit threshold, follow-up SSH/HTTP traffic from that source is eligible for honeypot redirection.

## Important Limitation

The first packets of a new connection may still reach the real service before NTTH has enough evidence to classify the source as suspicious. This is intentional to reduce false positives. After the source becomes suspicious, follow-up SSH/HTTP attempts are redirected to honeypot.
