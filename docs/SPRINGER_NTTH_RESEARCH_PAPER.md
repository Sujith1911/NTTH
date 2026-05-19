# NTTH: A Lab-Validated Event-Driven Security Gateway for Transparent Risk Scoring, Honeypot Evidence Collection, and Reversible Client Containment

## Authors and Affiliations

[Author 1], [Author 2], [Author 3]  
Department of [Department Name], [University Name], [City], [Country]  
Email: [email1], [email2], [email3]

## Abstract

Small laboratories, classrooms, home networks, and Internet-of-Things deployments frequently lack affordable mechanisms for observing client traffic, collecting attack evidence, and applying reversible containment. Mature intrusion detection systems and honeypots provide important building blocks, but they are commonly deployed as separate tools and often require non-trivial integration before they can demonstrate a complete defensive workflow. This paper presents NTTH, a low-cost event-driven security gateway prototype that converts an Ubuntu host with a USB wireless adapter into a protected Wi-Fi gateway. Client traffic is routed through the gateway, packet metadata is inspected, rule-assisted anomaly scores are converted into transparent risk decisions, and high-risk clients are contained through Linux firewall rules that stop Internet forwarding while preserving Wi-Fi association and administrative visibility. NTTH also integrates Cowrie SSH honeypot and lightweight service decoys to capture credentials, commands, source identity, and session timelines. The contribution is an applied systems architecture for closed-loop observe--score--decide--contain--report behavior in a reproducible university-scale environment. The paper describes the architecture, scoring model, containment workflow, measurement instrumentation, ethical constraints, and evaluation protocol required to quantify detection outcome, false positives, latency, resource usage, database growth, and block/unblock correctness. Initial implementation verification confirms that NTTH operates as a real gateway prototype; final quantitative claims should be reported only after the live experiments defined in this paper are executed.

**Keywords:** network security, intrusion detection, honeypot, risk scoring, event-driven architecture, gateway security, cyber deception, nftables, Cowrie, cybersecurity education

## 1 Introduction

Network security research often assumes that defenders can deploy managed switches, enterprise firewalls, endpoint agents, and centralized monitoring. Smaller environments are different. A university laboratory, a project demonstration bench, or a small IoT testbed may have only commodity hardware, mobile clients, and limited administrative time. In such settings, the difficult part is not only detecting a suspicious packet; it is building a complete, understandable, and reproducible defensive loop from observation to response.

Established systems such as Snort and Suricata provide mature packet inspection and rule-driven detection capabilities [1, 2]. Cowrie and related honeypots capture attacker interaction and provide useful behavioral evidence [3]. Public datasets and machine-learning studies support broader intrusion detection research [4-7]. Yet a student or small laboratory still faces a systems problem: how to place the monitor in the traffic path, relate packet observations to device identity, preserve evidence, apply reversible containment, and present the result in a way that can be inspected by a human operator.

NTTH addresses this problem as a lab-validated security gateway prototype. The gateway hosts a protected Wi-Fi network, assigns client addresses, captures routed packet metadata, scores behavior, applies firewall response, and exposes dashboards for topology, packet inspection, firewall state, honeypot sessions, and system health. The design deliberately avoids claiming production-grade IDS accuracy or full autonomous intelligence. Instead, it focuses on a measurable and defensible systems contribution: a low-cost event-driven architecture for transparent risk scoring and reversible containment of protected Wi-Fi clients.

The main contributions are:

1. An inline gateway deployment model that avoids passive Wi-Fi visibility limitations by routing protected clients through the NTTH host.
2. An event-driven modular pipeline that links packet observation, scoring, decision, enforcement, and reporting.
3. A transparent risk-scoring model that records rule evidence, score components, action reason, and final containment decision.
4. A reversible forwarding-layer containment mechanism that blocks Internet access while keeping the client visible to the administrator.
5. Honeypot-assisted evidence collection through Cowrie and service decoys.
6. Research instrumentation for measuring false positives, detection outcomes, capture-to-enforcement latency, event-bus backlog, resource usage, and database growth.

## 2 Background and Literature Review

### 2.1 Network Intrusion Detection

Network intrusion detection systems inspect traffic and generate alerts when packet patterns or learned behavior deviate from expected activity. Signature-based tools remain valuable because they provide interpretable rules, but they require frequent updates and may miss novel or slow attacks. Learning-based approaches address some of these limitations but introduce dataset bias, feature drift, and explainability concerns, especially in IoT and edge environments [4, 5]. Surveys of IoT intrusion detection emphasize that deployment strategy and validation methodology are as important as classifier selection [6].

NTTH does not compete with mature IDS engines on signature depth. Its detection layer is intentionally described as rule-assisted anomaly scoring. This choice improves transparency and reduces the risk of unsupported machine-learning claims. Future versions can train models on gateway baseline traffic or public datasets such as CICIDS2017 and Edge-IIoTset [7, 8], but the current prototype is evaluated as a systems gateway rather than as a new classifier.

### 2.2 Honeypots and Defensive Deception

Honeypots are controlled decoy services that collect evidence about unauthorized interaction. Cowrie is widely used for SSH/Telnet deception and can record credential attempts and shell commands [3]. Recent deception research discusses the value of decoys, honeytokens, moving-target defense, and attacker engagement, but also warns that weakly emulated services are often detectable by skilled adversaries [9, 10]. For this reason, NTTH frames its honeypot layer as educational and evidence-oriented. Cowrie is useful for controlled demonstrations, commodity scans, and low-to-medium sophistication interactions; it is not presented as a complete deception platform against advanced operators.

### 2.3 Automated Response and Gateway Security

Automated response systems reduce the delay between detection and containment, but they also risk harming legitimate users if false positives are not controlled. Edge and IoT gateways are attractive enforcement points because they observe traffic from many constrained devices without requiring endpoint agents. NTTH adopts this gateway position and implements policy-driven automated response: risk thresholds map to log, rate-limit, honeypot redirect, or block actions. The policy is transparent and configurable rather than self-learning.

### 2.4 Research Gap

The gap addressed by NTTH is not the absence of packet capture, honeypots, or firewall technology. The gap is a reproducible university-scale architecture that combines these components into a measurable closed loop while preserving operator visibility. Existing individual tools document their own capabilities, but they do not provide a single low-cost workflow for protected hotspot deployment, transparent risk scoring, honeypot evidence capture, reversible forwarding-layer containment, and live dashboard inspection.

## 3 Problem Definition

Let a protected network contain a set of client devices \(D=\{d_1,d_2,\ldots,d_n\}\) connected through a gateway \(G\). For each observed packet or session event \(e_t\), the gateway must decide whether the originating device should be allowed, logged, throttled, redirected, or blocked. The problem is constrained by four requirements:

1. **Visibility:** The gateway must observe protected client traffic without relying on unreliable passive wireless monitoring.
2. **Transparency:** The reason for a risk score and action must be inspectable.
3. **Reversibility:** A containment action must be removable by an administrator without disconnecting the client from Wi-Fi.
4. **Measurability:** The system must expose enough telemetry to evaluate false positives, latency, overhead, and storage cost.

The defensive objective is not to identify the physical location of an attacker or perform covert tracking. Ethical use is limited to owned devices, authorized experiments, and consent-based monitoring.

## 4 Proposed Framework / Methodology

NTTH follows an observe--score--decide--contain--report workflow:

1. **Observe:** Capture IPv4 packets from the protected gateway path and extract metadata such as IP addresses, ports, protocol, TCP flags, packet length, HTTP fields, TLS SNI/ALPN hints where visible, QUIC hints, and flow identifiers.
2. **Score:** Evaluate rule evidence for scans, floods, brute force behavior, honeypot interaction, and anomalous traffic volume.
3. **Decide:** Convert risk score into one of four actions: log, rate-limit, redirect, or block.
4. **Contain:** Apply nftables rules for forwarding-layer response.
5. **Report:** Store events, packet metadata, firewall state, honeypot sessions, and research telemetry.

The methodology favors traceability over opaque accuracy claims. Every high-risk decision records the rule evidence, score components, selected action, and final enforcement status. This allows a reviewer to inspect not only whether the system reacted, but why it reacted.

## 5 System Architecture

### 5.1 Deployment Model

The prototype runs on Ubuntu with a USB wireless adapter capable of access point mode. The host creates the `NTTH-Secure` hotspot, assigns addresses in `192.168.4.0/24`, and exposes the dashboard at `192.168.4.1:8001`. Protected clients route through the gateway. The upstream interface provides Internet connectivity.

**Figure 1: NTTH Gateway Deployment.**  
Place after this paragraph. The figure should show Internet/upstream network, Ubuntu gateway, protected Wi-Fi hotspot, mobile clients, packet capture, risk scoring, nftables enforcement, Cowrie container, database, and dashboard.

### 5.2 Event-Driven Modular Pipeline

The backend uses an asynchronous event bus. Packet capture publishes `device_seen` events. The threat stage evaluates packet features and publishes `threat_detected`. The decision stage publishes `enforcement_action`. The enforcement stage applies firewall or honeypot actions and emits reporting events. This should be described as an event-driven modular pipeline, not a multi-agent AI system.

**Figure 2: Event-Driven Processing Pipeline.**  
Place after this paragraph. Show packet capture, feature extraction, threat scoring, decision policy, enforcement, reporting, dashboard, and research metrics recorder.

### 5.3 Data and Evidence Storage

The system stores device identity, packet metadata, threat events, firewall rules, honeypot sessions, system logs, and research metrics. The research metrics are written to JSONL and exported as CSV for paper analysis. They include experiment labels, event stage, trace identifier, source/destination fields, scores, actions, and capture-to-enforcement latency.

**Figure 3: Data Model and Evidence Flow.**  
Place after this paragraph. Show devices, captured packets, threat events, firewall rules, honeypot sessions, and research metrics.

### 5.4 Dashboard

The dashboard provides topology, packet inspector, firewall rules, honeypot sessions, device detail, and system health views. Its intended user is a university lab operator, project evaluator, or junior security analyst. It is not positioned as a replacement for a production SOC platform.

## 6 Algorithm or Workflow Description

### 6.1 Risk Scoring Model

For each event \(e_t\), a rule score \(R(e_t)\) is computed from detector outputs:

\[
R(e_t)=\max(S_{scan}, S_{syn}, S_{brute}, S_{honeypot}, S_{other})
\]

where \(S_{scan}\), \(S_{syn}\), and \(S_{brute}\) represent normalized evidence for port diversity, SYN volume, and repeated authentication or honeypot interaction. A heuristic anomaly score \(A(e_t)\) may be computed from traffic features. The final risk score is:

\[
\rho(e_t)=\min(1.0, \max(R(e_t), A(e_t)))
\]

If the deployed code uses a different formula, the final paper must replace this equation with the exact implementation. The important research requirement is that the formula must be disclosed and reproducible.

### 6.2 Action Mapping

The current policy maps risk to response:

| Risk Range | Action | Interpretation |
|---|---|---|
| \(0.00 \leq \rho < 0.20\) | Allow | No incident is emitted |
| \(0.20 \leq \rho < 0.60\) | Log | Suspicious evidence is recorded |
| \(0.60 \leq \rho < 0.75\) | Rate-limit | Source is throttled |
| \(\rho \geq 0.75\) | Block | Source loses Internet forwarding |

The thresholds are hand-tuned for controlled lab evaluation. They should not be presented as globally optimal. A deployment should tune them using baseline traffic and a labeled validation set.

### 6.3 Containment Workflow

When a source crosses the block threshold, NTTH installs a forwarding-layer nftables rule equivalent to:

```text
ip saddr <client-ip> drop
```

This stops Internet forwarding but keeps the device associated with Wi-Fi. The administrator can remove the rule through Clear Risk and Unblock. This design improves observability but has a known limitation: local subnet attacks may still be possible unless optional local-isolation rules are enabled.

### 6.4 Research Telemetry Workflow

The instrumentation records:

1. packet observed;
2. threat scored;
3. decision made;
4. report emitted;
5. enforcement started;
6. enforcement completed.

The capture-to-enforcement latency is:

\[
L = t_{enforcement\_done} - t_{packet\_observed}
\]

This supports a measurable near-real-time claim. The system should not claim hard real-time behavior because no bounded worst-case scheduling guarantee is provided.

## 7 Experimental Setup

### 7.1 Hardware and Software

The final paper must report exact hardware. The current reproducibility template is:

| Component | Value to Report |
|---|---|
| Gateway CPU | 12th Gen Intel Core i7-1255U, 12 logical CPUs |
| Gateway RAM | 15 GiB RAM, 4 GiB swap |
| Operating system | Ubuntu 24.04.4 LTS |
| Kernel | Linux 6.17.0-22-generic |
| Wi-Fi adapter | Qualcomm Atheros AR9271 802.11n USB |
| Python | 3.12.3 |
| Backend framework | FastAPI 0.110.0 |
| Packet library | Scapy 2.5.0 |
| Database | SQLite via SQLAlchemy 2.0.29 |
| Honeypot | Cowrie container |
| Firewall | nftables 1.0.9 project chains |
| Access point service | hostapd 2.10 |

### 7.2 Experiment Matrix

| Scenario | Duration/Runs | Purpose |
|---|---:|---|
| Idle connected phone | 10 min | Baseline noise |
| Normal browsing | 10 min | False-positive measurement |
| Video streaming | 10 min | Benign high-throughput stress |
| App update/download | 10 min | Benign burst traffic |
| DNS-heavy browsing | 5 min | DNS false-positive check |
| SSH honeypot | 3 sessions | Credential/command evidence |
| HTTP honeypot | 3 sessions | HTTP evidence capture |
| Port scan | 3 runs | Detection and latency |
| Burst traffic/ping flood | 3 runs | Rate-limit/block behavior |
| Block/unblock | 3 runs | Containment correctness |

All experiments must be executed only on devices owned by the authors and connected to the isolated NTTH hotspot.

## 8 Results and Discussion

This section must be filled using exported metrics from:

```text
/api/v1/research/metrics/export.csv
/api/v1/research/metrics/export.jsonl
```

No synthetic values should be inserted. Until the experiments are executed, the following tables remain measurement placeholders.

### 8.1 Detection Outcome

| Scenario | Runs | Detected | Missed | Dominant Action | Evidence |
|---|---:|---:|---:|---|---|
| Port scan | TBD | TBD | TBD | TBD | ports/time window |
| SSH honeypot | TBD | TBD | TBD | TBD | credentials/commands |
| HTTP honeypot | TBD | TBD | TBD | TBD | paths/form fields |
| Burst traffic | TBD | TBD | TBD | TBD | packet rate |

### 8.2 False Positive Analysis

| Benign Scenario | Duration | Threat Events | Max Risk | Wrong Block | Notes |
|---|---:|---:|---:|---|---|
| Idle phone | TBD | TBD | TBD | TBD | TBD |
| Browsing | TBD | TBD | TBD | TBD | TBD |
| Video streaming | TBD | TBD | TBD | TBD | TBD |
| App download/update | TBD | TBD | TBD | TBD | TBD |

### 8.3 Latency

| Scenario | Samples | Min ms | Avg ms | Max ms |
|---|---:|---:|---:|---:|
| Packet to block | TBD | TBD | TBD | TBD |
| Packet to rate-limit | TBD | TBD | TBD | TBD |
| Honeypot event to report | TBD | TBD | TBD | TBD |

### 8.4 Resource Usage

| Scenario | Load 1m | Max RSS KB | Event Bus Backlog | Dropped Events | DB Size MB |
|---|---:|---:|---:|---:|---:|
| Idle | TBD | TBD | TBD | TBD | TBD |
| Browsing | TBD | TBD | TBD | TBD | TBD |
| Attack | TBD | TBD | TBD | TBD | TBD |

### 8.5 Discussion

The expected discussion should interpret three outcomes. First, if benign experiments show no wrong block, the threshold policy is acceptable for a laboratory gateway. Second, if attack experiments produce consistent detection and containment, NTTH supports the claim of policy-driven automated response. Third, if event-bus drops or database growth are high, the limitations section must treat throughput and retention as engineering constraints rather than minor details.

## 9 Comparative Evaluation

The comparison must be fair. NTTH should not be compared as if it were equivalent to mature IDS platforms. The correct comparison is architectural.

| System Category | Strength | Limitation Compared with NTTH | NTTH Limitation Compared with It |
|---|---|---|---|
| Snort/Suricata IDS | Mature signatures and protocol inspection | Requires integration for hotspot containment and honeypot evidence | NTTH has much smaller detector coverage |
| Cowrie honeypot | Strong SSH/Telnet interaction logging | Does not provide gateway risk scoring or firewall containment | NTTH decoys are less mature beyond Cowrie |
| Security Onion/Wazuh-style stacks | Rich monitoring and SOC workflow | Heavier deployment for small lab demonstration | NTTH lacks production hardening and analytics depth |
| pfSense/Snort-style gateway | Practical firewall/IDS appliance model | Honeypot evidence and research telemetry need extra integration | NTTH has lower performance and maturity |
| NTTH | Low-cost integrated lab gateway with reversible containment | Not production-grade; lab-scale evaluation | Requires measured validation for main-track claims |

## 10 Limitations

NTTH has several limitations. The detector set is narrow and focuses on scans, floods, brute force indicators, and honeypot interactions. Thresholds are hand-tuned and require empirical calibration. Blocking is IP-based, so DHCP churn can reduce persistence unless MAC-aware containment is added. Forward-chain blocking stops Internet access but may not prevent local subnet abuse. IPv6, fragmented-packet reassembly, VPN/tunnel visibility, and advanced protocol evasion are not fully handled. Cowrie is useful for commodity SSH interaction but is not a complete deception platform against skilled adversaries. The dashboard and WebSocket management plane require strict authentication and should not be exposed without hardening. The backend should be decomposed so privileged packet/firewall operations are separated from the web application.

## 11 Conclusion

NTTH demonstrates a practical event-driven security gateway that joins packet observation, transparent risk scoring, honeypot evidence, and reversible forwarding-layer containment in a low-cost laboratory setting. Its strongest contribution is not a new IDS classifier but a reproducible closed-loop systems architecture for protected Wi-Fi clients. The implementation now includes research telemetry that can support peer-reviewable evaluation. With measured false-positive, latency, throughput, resource, and block/unblock results, NTTH can be positioned as a defensible applied systems-security paper for a workshop, demo track, or appropriately scoped conference submission.

## 12 Future Work

Future work includes MAC-aware identity and containment, nftables-only NAT/rule management, IPv6 monitoring, fragment reassembly, VPN/tunnel indicators, fuzz testing for protocol parsers, stronger HTTP honeypot realism, IOC extraction from honeypot commands, dashboard hardening, least-privilege firewall helpers, public dataset validation, longer soak testing, and comparison against integrated open-source security stacks.

## References

[1] Snort, "Network Intrusion Detection and Prevention System." Available: https://www.snort.org/  

[2] Suricata, "Suricata User Guide." Open Information Security Foundation. Available: https://docs.suricata.io/  

[3] Cowrie, "Cowrie SSH/Telnet Honeypot." Available: https://docs.cowrie.org/  

[4] S. Abdelhamid, M. Aref, I. Hegazy, and R. M. Roushdy, "A Survey on Learning-Based Intrusion Detection Systems for IoT Networks," in *Proc. ICICIS*, 2021, pp. 278-288, doi: 10.1109/ICICIS52592.2021.9694226.  

[5] A. A. Diro and N. Chilamkurti, "Intrusion Detection in Internet of Things Systems: A Review on Design Approaches Leveraging Multi-Access Edge Computing, Machine Learning, and Datasets," *Sensors*, 2022.  

[6] A. Khraisat and A. Alazab, "A critical review of intrusion detection systems in the internet of things: techniques, deployment strategy, validation strategy, attacks, public datasets and challenges," *Cybersecurity*, vol. 4, article 18, 2021, doi: 10.1186/s42400-021-00077-7.  

[7] Canadian Institute for Cybersecurity, "CICIDS2017 Dataset." Available: https://www.unb.ca/cic/datasets/ids-2017.html  

[8] A. Ferrag, O. Friha, L. Maglaras, H. Janicke, and L. Shu, "Edge-IIoTset: A New Comprehensive Realistic Cyber Security Dataset of IoT and IIoT Applications for Centralized and Federated Learning," *IEEE Access*, vol. 10, pp. 40281-40306, 2022, doi: 10.1109/ACCESS.2022.3165809.  

[9] J. Pawlick, E. Colbert, and Q. Zhu, "A Game-Theoretic Taxonomy and Survey of Defensive Deception for Cybersecurity and Privacy," *ACM Computing Surveys*, vol. 52, no. 4, 2019, doi: 10.1145/3337772.  

[10] M. H. Almeshekah and E. H. Spafford, "Cyber Security Deception," in *Cyber Deception: Building the Scientific Foundation*, Springer, 2016.  

[11] F. T. Liu, K. M. Ting, and Z.-H. Zhou, "Isolation Forest," in *Proc. IEEE International Conference on Data Mining*, 2008, pp. 413-422, doi: 10.1109/ICDM.2008.17.  

[12] Scapy Project, "Scapy Documentation." Available: https://scapy.readthedocs.io/  

[13] Netfilter Project, "nftables Wiki." Available: https://wiki.netfilter.org/wiki-nftables/  

[14] hostapd, "Linux wireless host access point daemon." Available: https://w1.fi/hostapd/  
