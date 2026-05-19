# NTTH: A Real-Time Gateway-Based Autonomous Defense Architecture with Risk-Aware Containment and Honeypot Intelligence

**Author(s):** [Your Name], [Team Member 2], [Team Member 3]  
**Affiliation:** Department of [Department Name], [University Name], [City], [Country]  
**Email:** [email1]@[domain], [email2]@[domain], [email3]@[domain]

---

## Abstract

Small campus, laboratory, home, and Internet-of-Things networks often lack a practical security gateway that can observe device traffic, detect attacks, apply containment, and preserve evidence without requiring enterprise hardware or a full security operations team. Existing intrusion detection systems are strong at packet inspection and alert generation, while honeypots are strong at attacker interaction capture; however, these components are commonly deployed as separate tools and do not form a simple closed-loop gateway for university-scale demonstration and controlled defense. This paper presents **NTTH (No Time To Hack)**, a real-time working lab prototype that converts an Ubuntu laptop into a protected Wi-Fi gateway. Devices connect to the `NTTH-Secure` hotspot, traffic is routed through the gateway, packets are inspected, device risk is scored, and enforcement is applied using Linux nftables. High-risk devices remain connected to Wi-Fi but lose Internet forwarding until an administrator clears risk and unblocks them. NTTH also integrates Cowrie SSH honeypot and multi-protocol honeypots to capture attempted credentials, commands, source device identity, and session timelines. The novelty of the work lies in the integrated gateway architecture: inline hotspot placement, asynchronous agent-inspired processing, explainable risk scoring, forward-chain containment, honeypot intelligence, and a live dashboard packaged as one deployable academic prototype. The system was validated in a controlled lab using mobile devices connected to the protected hotspot and attacks including SSH honeypot interaction, HTTP honeypot requests, ping/port scans, and controlled traffic bursts. Results show that NTTH functions as a real-time working prototype rather than a simulated dashboard, making it suitable for university project demonstration and research paper presentation.

**Index Terms:** Intrusion detection, autonomous defense, honeypot, Cowrie, nftables, packet inspection, Wi-Fi gateway, risk scoring, cybersecurity education, network topology.

---

## I. Introduction

Modern networks are increasingly composed of mobile phones, laptops, embedded devices, smart appliances, and laboratory systems. These devices often connect to open or lightly managed networks where attacks such as port scanning, weak credential attempts, brute force login trials, and denial-of-service traffic can occur with minimal setup. In enterprise environments, security monitoring may be handled by dedicated IDS/IPS appliances, centralized logging, endpoint agents, and security operations teams. In a university laboratory or final-year project environment, however, the challenge is different: the system must be understandable, demonstrable, low-cost, and capable of showing a full security workflow end to end.

Traditional IDS tools such as Snort and Suricata are widely used for network intrusion detection and prevention. Snort is described by its official project as an open-source IPS that uses rules to identify malicious packet activity and generate alerts or stop packets when deployed inline [1]. Suricata is documented as a high-performance network IDS, IPS, and network security monitoring engine [2]. These systems are mature, but building a student-demonstrable closed loop around them still requires deployment design, policy configuration, response automation, evidence capture, and visualization.

Honeypots solve a different problem. Cowrie, for example, is a medium to high interaction SSH/Telnet honeypot designed to log brute-force attacks and shell interactions [3]. Honeypots are excellent for observing attacker behavior, but by themselves they do not decide when a normal connected client should be contained, when Internet forwarding should be stopped, or how to present the security state of every protected device.

This paper presents NTTH, a gateway-based autonomous defense prototype designed for a controlled university demonstration. The key idea is to place the security system directly in the path of protected devices. NTTH creates a Wi-Fi hotspot, assigns client IP addresses, routes traffic, captures packets, scores device behavior, applies firewall policy, and displays topology, packet, firewall, and honeypot views in a browser dashboard. Unlike a purely simulated demo, the system handles real connected devices and real packets from the test network.

The main contributions of this work are:

1. **Inline protected hotspot architecture:** NTTH places the defense host as the gateway for connected devices, solving the visibility problem of passive Wi-Fi monitoring.
2. **Agent-inspired closed-loop pipeline:** Packet capture, threat assessment, decision-making, enforcement, reporting, and dashboard updates are connected through an asynchronous event-driven backend.
3. **Risk-aware containment:** Devices crossing the configured high-risk threshold are blocked using nftables forward-chain rules, stopping Internet access while keeping Wi-Fi association and local administrative visibility.
4. **Honeypot intelligence integration:** Cowrie SSH and HTTP/multi-protocol honeypots capture attempted credentials, commands, and session metadata and associate them with dashboard events.
5. **Explainable dashboard:** Packet inspector, topology, firewall, honeypot, and risk detail panels expose why a device was classified as suspicious or blocked.
6. **Low-cost academic deployability:** The prototype runs on commodity Ubuntu hardware with a USB Wi-Fi adapter and mobile devices for testing.

---

## II. Research Gap and Novelty Statement

### A. Identified Research Gaps

The project addresses the following practical research gaps:

**Gap 1: Detection without immediate, demonstrable containment.**  
Many IDS deployments focus on alerting. In a university demo, an alert alone is less convincing than showing that the attacking device loses Internet access while remaining visible in the network.

**Gap 2: Separate IDS and honeypot workflows.**  
IDS tools and honeypots are often deployed as separate systems. NTTH links detection, risk scoring, containment, and honeypot evidence into one dashboard.

**Gap 3: Passive Wi-Fi visibility limitations.**  
A device on the same wireless LAN cannot reliably observe all unicast traffic between other clients. NTTH avoids this by becoming the access point/gateway for the protected network.

**Gap 4: Lack of explainability in student prototypes.**  
Many security demos show only a final alert. NTTH shows packet details, risk reasons, firewall state, topology state, and honeypot sessions.

**Gap 5: Blocking that disconnects or hides the client.**  
Deauthentication or Wi-Fi disconnection prevents continued observation. NTTH keeps the device associated but blocks Internet forwarding using firewall rules, making the state reversible through the dashboard.

### B. Novelty Claim

The novelty of NTTH is not that it invents packet capture, IDS rules, honeypots, or firewalls individually. The novelty is the **integrated gateway-level closed-loop architecture**:

> NTTH combines protected hotspot routing, real-time packet inspection, explainable risk scoring, nftables forward-chain containment, honeypot evidence capture, and a live dashboard into one low-cost working academic prototype.

This is a defensible novelty claim because the system demonstrates the complete Observe-Analyze-Decide-Act-Report cycle on live connected devices, rather than presenting a static IDS alert or simulated dashboard.

### C. Research Gap Fulfillment Matrix

| Research Gap | NTTH Design Response | Demonstrable Evidence |
|---|---|---|
| IDS alerts do not always show response | Risk score is mapped to firewall action | Device risk crosses threshold and Internet forwarding stops |
| IDS and honeypot evidence are separate | Cowrie and HTTP honeypot events are stored and shown in the same dashboard | Honeypot Center shows credentials, commands, source IP, and timeline |
| Passive Wi-Fi capture is unreliable for all clients | NTTH becomes the hotspot gateway | Connected device traffic appears in Packet Inspector |
| Security demos often hide reasoning | Risk details, packet rows, firewall rule reasons, and topology state are exposed | Reviewer can click device/packet/firewall views |
| Blocking disconnects the client from observation | nftables forward-chain block keeps Wi-Fi connected but stops Internet forwarding | Phone remains connected to `NTTH-Secure` while `curl` to Internet fails |
| Student prototypes often use mock traffic only | Demo uses real mobile devices, Termux commands, SSH honeypot sessions, and live firewall rules | Real packet timestamps, command logs, and kernel firewall state are visible |

---

## III. Related Work

### A. Rule-Based IDS/IPS

Snort and Suricata represent mature rule-based intrusion detection and prevention systems. Snort uses rules to detect malicious packet activity and can be deployed as a sniffer, packet logger, IDS, or inline IPS [1]. Suricata provides IDS, IPS, and network security monitoring capabilities [2]. These platforms are powerful but require careful integration with response policy, topology visualization, and honeypot evidence capture for a complete academic demo.

### B. Honeypot Systems

Cowrie is a widely used SSH/Telnet honeypot that logs brute-force attempts and shell interaction [3]. It can emulate a UNIX-like system and capture typed commands. NTTH uses Cowrie as a deception and evidence component, but adds gateway placement, risk scoring, firewall action, and dashboard correlation.

### C. Machine Learning and Anomaly Detection

Isolation Forest was introduced by Liu, Ting, and Zhou as an anomaly detection method that isolates anomalies instead of profiling normal points [4]. NTTH's architecture allows rule scores and anomaly-style scoring to contribute to device risk. In the current university-demo form, the emphasis is on explainable operational behavior rather than claiming a large benchmark accuracy result.

### D. Benchmark IDS Datasets

CICIDS2017 is a commonly used intrusion detection evaluation dataset containing realistic benign and attack traffic for IDS research [5]. It is useful for future formal benchmarking. NTTH's current validation is based on controlled real-device lab testing; future work can extend this with public benchmark evaluation.

### E. Linux Firewall Enforcement

nftables allows user-defined chains attached to Netfilter hooks such as input, forward, and prerouting [6]. NTTH uses this capability to create project-owned firewall chains. The important implementation decision is to block risky clients in the **forward** path, not by disconnecting them from Wi-Fi or blocking dashboard access.

---

## IV. Proposed System Architecture

### A. Deployment Model

NTTH is deployed on an Ubuntu laptop or desktop acting as a protected Wi-Fi gateway:

- Upstream interface: provides Internet access.
- Protected interface: hosts the `NTTH-Secure` Wi-Fi hotspot.
- Gateway IP: `192.168.4.1`.
- Protected clients: mobile/laptop devices connected to the hotspot.
- Dashboard: available at `http://192.168.4.1:8001`.

All protected client traffic passes through the Ubuntu gateway. This enables packet observation, risk scoring, and firewall control from a single machine.

**Figure 1 Placeholder: NTTH Deployment Architecture**  
*Insert image here.*  
Description: Show Internet/upstream network connected to Ubuntu gateway. The gateway hosts `NTTH-Secure`, DHCP/NAT, packet capture, firewall, honeypots, database, and dashboard. Mobile devices connect to the protected Wi-Fi.

### B. Backend Processing Pipeline

The backend is implemented using FastAPI and asynchronous Python services. The pipeline is:

1. Packet sniffer captures IP traffic from the protected interface.
2. Feature extractor extracts packet metadata such as IPs, ports, protocol, TCP flags, size, HTTP fields, TLS hints, QUIC hints, and flow IDs.
3. Threat agent evaluates the packet using rule logic and anomaly scoring.
4. Decision agent maps risk to action.
5. Enforcement agent applies nftables rules or honeypot routing.
6. Reporting agent stores events and broadcasts live updates.
7. Dashboard displays topology, packets, firewall rules, honeypot sessions, and risk details.

**Figure 2 Placeholder: Agent-Inspired Event Pipeline**  
*Insert image here.*  
Description: Show packet capture -> feature extraction -> threat agent -> decision agent -> enforcement agent -> reporting agent -> dashboard, connected through an event bus.

### C. Data Storage

The system stores:

- Devices and their risk state.
- Captured packet metadata.
- Threat events and risk reasons.
- Firewall rules and active containment status.
- Honeypot sessions, credentials, commands, and timelines.
- System health and runtime status.

**Figure 3 Placeholder: Database Schema Summary**  
*Insert image here.*  
Description: Show tables for devices, captured_packets, threat_events, firewall_rules, honeypot_sessions, and users with relationships.

### D. Dashboard Architecture

The frontend is a Flutter web dashboard served by the backend. It includes:

- Dashboard overview.
- Network topology.
- Packet inspector.
- Firewall controls.
- Honeypot center.
- Device details.
- System health.

WebSocket updates are used for live events. Polling and refresh actions are also used so the dashboard recovers after hotspot restarts.

**Figure 4 Placeholder: Dashboard Screenshots**  
*Insert image here.*  
Description: Include screenshots of topology, packet inspector, firewall rules, honeypot captured commands, and system health.

---

## V. Core Modules

### A. Packet Inspector

The packet inspector provides a Wireshark-inspired view of stored packet metadata. It supports protocol filters, source/destination filters, date filters, search, flow view, and export. Captured fields include:

- Source and destination IP.
- Source and destination port.
- Protocol.
- TCP flags, sequence and acknowledgement metadata.
- UDP length and ICMP fields.
- Packet length and payload preview.
- HTTP method, host, path, user agent, content type, body preview, and form fields for plain HTTP.
- TLS SNI/ALPN hints where visible.
- QUIC hint.
- Flow ID.

**Figure 5 Placeholder: Packet Inspector Detail View**  
*Insert image here.*  
Description: Show selected packet with protocol header details, HTTP fields, TLS metadata, hex/ASCII preview, and flow conversation.

### B. Risk Scoring

The risk score is normalized between 0 and 1. The current demo policy is:

| Risk Range | Action | Meaning |
|---|---|---|
| < 0.20 | Allow | Normal traffic |
| 0.20-0.59 | Log | Suspicious but not contained |
| 0.60-0.74 | Rate-limit | Noisy or suspicious behavior |
| >= 0.75 | Block | High-risk device containment |

The threshold of 0.75 was selected for the university demo because it clearly demonstrates automatic containment while still avoiding immediate blocking for medium-risk noise.

### C. Firewall Containment

The firewall uses nftables project-owned chains. The most important rule is the block behavior:

```text
ip saddr <blocked-device-ip> drop
```

This rule is attached to a forward-chain hook. Therefore:

- The device remains connected to Wi-Fi.
- The device can still appear in topology.
- Internet forwarding is stopped.
- The administrator can still clear risk and remove the rule.

This is safer and more demonstrable than disconnecting the client from Wi-Fi.

**Figure 6 Placeholder: Block/Unblock Flow**  
*Insert image here.*  
Description: Show high-risk device -> risk >= 75% -> nftables forward drop -> Internet stops -> Clear Risk & Unblock -> rule removed -> Internet restored.

### D. Honeypot Intelligence

Cowrie SSH honeypot listens on the demo honeypot port and captures:

- Source IP.
- Username attempts.
- Password attempts.
- Commands typed after login.
- Session duration.

The HTTP/multi-protocol honeypots capture HTTP requests and service interactions. This makes the demo stronger because the system does not merely block; it also gathers evidence of attacker behavior.

**Figure 7 Placeholder: Honeypot Session Evidence**  
*Insert image here.*  
Description: Show captured SSH login attempt, password, commands such as `whoami`, `cat /etc/passwd`, and session duration.

### E. Topology View

The topology view represents:

- Gateway/router.
- NTTH server.
- Connected devices.
- Blocked/risky devices.
- Honeypot node.
- Attack edges or honeypot session links.

Recent fixes ensure that local LAN attackers are shown as local devices rather than incorrectly appearing as external attackers when the device table is temporarily stale after hotspot restart.

**Figure 8 Placeholder: Live Network Topology**  
*Insert image here.*  
Description: Show gateway, NTTH server, connected phone, honeypot, risk color, and blocked state.

---

## VI. Novel Architecture Comparison

| Feature | Snort/Suricata IDS/IPS | Cowrie Honeypot | Typical Student Simulation | NTTH |
|---|---|---|---|---|
| Real connected clients | Depends on deployment | No | Usually no | Yes |
| Protected hotspot gateway | No by default | No | Usually no | Yes |
| Packet inspection | Yes | No | Often mocked | Yes |
| Honeypot command capture | No | Yes | Often mocked | Yes |
| Automatic risk scoring | Rule alerts | No | Often simplified | Yes |
| Device-level Internet block | Inline IPS possible, needs setup | No | Usually simulated | Yes |
| Device stays Wi-Fi connected while blocked | Not the main focus | No | Rare | Yes |
| Dashboard topology | External tools needed | No | Often static | Yes |
| Clear risk and unblock | Requires integration | No | Often simulated | Yes |
| University demo readiness | High complexity | Partial | Easy but weak | High |

This table shows that NTTH's contribution is a complete academic prototype that integrates the important pieces in a single understandable system.

---

## VII. Methodology

### A. Test Environment

The test environment consists of:

- Ubuntu laptop/desktop running NTTH.
- USB Wi-Fi adapter hosting `NTTH-Secure`.
- Two mobile devices connected to the protected hotspot.
- Termux installed on Android devices for command-line testing.
- Dashboard accessed from the Ubuntu browser or connected client.

All tests are performed only on devices owned by the project team and connected to the isolated `NTTH-Secure` hotspot. No third-party network, public target, or unauthorized system is used during validation. Attack commands in this paper are included only as controlled lab test inputs for verifying detection, honeypot logging, and firewall containment.

### B. Test Scenarios

| Test Case | Tool/Command | Expected Result |
|---|---|---|
| Normal browsing | Browser/curl | Device appears, risk remains low |
| Ping test | `ping 192.168.4.1` | ICMP packets visible |
| Port scan | `nmap -sT -Pn ... 192.168.4.1` | Risk increases, packet inspector logs ports |
| SSH honeypot | `ssh -p 30022 root@192.168.4.1` | Cowrie captures username/password/commands |
| HTTP honeypot | `curl http://192.168.4.1:8888` | HTTP honeypot session logged |
| Block test | Repeated attack until risk >= 75% | Internet forwarding blocked |
| Unblock test | Clear Risk & Unblock | Firewall rule removed and Internet restored |

### C. Demo Commands

SSH honeypot:

```bash
ssh-keygen -R '[192.168.4.1]:30022'
ssh -p 30022 root@192.168.4.1
```

Commands inside honeypot:

```bash
whoami
ls
cat /etc/passwd
sudo su
wget http://evil.com/malware.sh
```

Port scan:

```bash
nmap -sT -Pn -p 21,22,23,80,443,445,3306,3389,5900,6379,8888,30022 192.168.4.1
```

Internet check after block:

```bash
curl -I http://example.com
```

Expected result: the blocked device remains connected to Wi-Fi but Internet access fails until unblocked.

---

## VIII. Results and Discussion

### A. Real-Time Working Behavior

The system was verified as a real-time working lab prototype:

- Mobile devices connect to the NTTH hotspot.
- Packets are captured from the protected gateway path.
- Attack traffic appears in Packet Inspector.
- Cowrie captures SSH username, password, and typed commands.
- Risk score increases during attack behavior.
- At high risk, the device is blocked.
- The blocked device remains associated with Wi-Fi.
- Internet forwarding stops for the blocked device.
- Clear Risk & Unblock removes the firewall rule and resets risk history.

**Figure 9 Placeholder: Blocked Device Evidence**  
*Insert image here.*  
Description: Show phone still connected to Wi-Fi, curl to Internet failing, dashboard showing device blocked, and firewall rule active.

### B. Honeypot Evidence

Cowrie successfully records command-level attacker behavior. This is important because it converts an attack from a simple alert into evidence.

Example captured fields:

- Username: `root`
- Password attempt: `[captured during demo]`
- Commands: `whoami`, `ls`, `cat /etc/passwd`, `sudo su`, `wget ...`
- Duration: session duration in seconds

**Figure 10 Placeholder: Captured Cowrie Commands**  
*Insert image here.*  
Description: Show Honeypot Center with captured credentials and commands.

### C. Topology Stability

After hotspot restart, topology can temporarily lose live device data while the network interface and DHCP state recover. NTTH mitigates this with:

- Faster topology refresh.
- Topology update events.
- Local honeypot attackers classified as local devices.
- Clear-risk-by-IP for stale/synthetic topology nodes.

### D. Why This Is Not Merely a Simulation

NTTH is not a simulated dashboard because the following operations are real:

- Wi-Fi clients physically connect to the gateway.
- Traffic is routed through Ubuntu.
- nftables rules are installed in the kernel firewall.
- Cowrie runs as a real honeypot container.
- SSH sessions and commands are captured from real clients.
- Internet access is actually blocked and restored.

The system should be described as a **real-time working lab prototype**, not as a production commercial firewall.

---

## IX. Limitations

The system has the following limitations:

1. It is designed for controlled lab and university demonstration, not enterprise production deployment.
2. HTTPS payloads are not decrypted. Only metadata such as IPs, ports, TLS SNI/ALPN hints, and QUIC hints may be visible.
3. Detection is rule/risk based and not equivalent to a commercial IDS signature feed.
4. Long-duration soak testing is still needed for continuous multi-day deployment.
5. Full byte-for-byte PCAP storage is not the main design goal; stored packet export is based on captured metadata and previews.
6. The hotspot depends on correct USB Wi-Fi adapter detection and Linux networking state.
7. Blocking is IP-based. If a device receives a new IP, the system must rediscover and reassess it.
8. Current testing is controlled-lab testing; future research can add CICIDS2017 benchmark evaluation and larger traffic datasets.

---

## X. Future Work

Future improvements include:

1. Public benchmark validation using CICIDS2017.
2. Longer live traffic testing with more devices.
3. Full PCAP capture and replay support.
4. More protocol parsers.
5. Better TLS certificate metadata extraction.
6. Stronger dashboard HTTPS and secret rotation.
7. Database backup/restore workflow.
8. More automated unit, API, and UI tests.
9. Optional LLM-assisted honeypot response generation.
10. MAC-aware containment for devices that change IP.

---

## XI. Conclusion

This paper presented NTTH, a real-time gateway-based autonomous defense prototype for university cybersecurity demonstration. NTTH creates a protected Wi-Fi hotspot, observes connected devices, analyzes packet metadata, assigns explainable risk, applies firewall containment, captures attacker behavior with honeypots, and displays the full workflow in a dashboard. The project fills a practical research and education gap by combining detection, response, deception, and visualization in one low-cost working system. The system is not positioned as a production commercial firewall; rather, it is a complete working lab prototype suitable for final-year project review, research presentation, and live demonstration to university project heads.

---

## References

[1] Snort, "Network Intrusion Detection & Prevention System." Official project page. Available: https://www.snort.org/  

[2] Suricata, "Suricata User Guide." Open Information Security Foundation. Available: https://docs.suricata.io/  

[3] Cowrie, "Cowrie SSH/Telnet Honeypot." Official documentation and repository. Available: https://docs.cowrie.org/ and https://github.com/cowrie/cowrie  

[4] F. T. Liu, K. M. Ting, and Z.-H. Zhou, "Isolation Forest," in *Proc. 8th IEEE International Conference on Data Mining*, 2008, pp. 413-422. DOI: 10.1109/ICDM.2008.17.  

[5] Canadian Institute for Cybersecurity, "CICIDS2017 Dataset." Available: https://www.unb.ca/cic/datasets/ids-2017.html  

[6] Netfilter Project, "Configuring chains - nftables wiki." Available: https://wiki.netfilter.org/wiki-nftables/index.php/Configuring_chains  

[7] Scapy Project, "Scapy Documentation." Available: https://scapy.readthedocs.io/  

[8] hostapd, "Linux wireless host access point daemon." Available: https://w1.fi/hostapd/  

---

## Appendix A: Suggested Figures to Capture from the Working Project

1. **System architecture diagram:** Draw the protected hotspot gateway and agent pipeline.
2. **Dashboard overview screenshot:** Show system health and live state.
3. **Topology before attack:** Phone connected, risk low.
4. **Packet inspector during scan:** Packets with TCP/UDP/ICMP filters.
5. **Cowrie session screenshot:** Username/password/commands.
6. **Blocked device screenshot:** Risk above threshold and blocked status.
7. **Phone Internet failure screenshot:** `curl -I http://example.com` fails while Wi-Fi remains connected.
8. **Unblock screenshot:** Clear Risk & Unblock and restored access.

## Appendix B: Demo Script for Project Heads

1. Start NTTH gateway mode.
2. Connect phone to `NTTH-Secure`.
3. Open dashboard at `http://192.168.4.1:8001`.
4. Show connected device in topology.
5. Run normal browsing and show low risk.
6. Run SSH honeypot command.
7. Show captured Cowrie credentials and commands.
8. Run nmap scan.
9. Show risk increase and packet inspector entries.
10. Wait for block at risk >= 75%.
11. Show phone still connected to Wi-Fi but Internet blocked.
12. Press Clear Risk & Unblock.
13. Show Internet restored.
