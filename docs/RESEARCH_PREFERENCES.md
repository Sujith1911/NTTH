# NTTH Research Paper Preferences

## Paper Type
- Novel Research Paper (NOT methodology comparison)
- System paper WITH experimental validation
- Agent-inspired autonomous pipeline (NOT "Agentic AI" — avoids overclaim)

## Target Venue
- IEEE Conference level (ICACCS / ICCCNT / ICICCS)

## Hardware
- Ubuntu laptop (IdeaPad 5 15IAL7)
- Atheros AR9271 USB WiFi adapter (monitor mode + injection)
- Mobile phone with Termux (attacker device)

## Research Focus
- DEFENSIVE security (NOT offensive)
- Autonomous closed-loop response
- Commodity hardware deployment

## Key Differentiators (vs reviewers)
1. Sub-second automated response (not just alerting) — MEASURE T1→T4 latency
2. Flow-aware honeypot deployment (not static) — unique vs AARF, AETHER, LLM Honeypot
3. Hybrid scoring with ablation-validated weights — grid search, not hand-tuned
4. Real implementation on real network (not simulation)
5. Dual dataset validation: 10K+ real packets + CICIDS2017 benchmark

## 3 Closest Papers to Differentiate Against
1. **AARF** (2024, IEEE) — RL-based game theory response, no latency measurement
2. **AETHER** (2025, TechRxiv) — AI-generated decoy assets, cloud-only, no flow-aware redirect
3. **LLM Agent Honeypot** (2024, arXiv) — Detects AI attackers, no enforcement/response

## Professor Feedback Priorities
1. P0 — Experiments with metrics (detection rate, latency, FP rate) — 10K+ packets
2. P0 — Comparison with Snort + Suricata (same attacks, same machine)
3. P0 — Ablation study (grid search weights + ROC curve analysis)
4. P0 — Multi-model ML comparison (IF vs RF vs SVM vs KNN vs DT)
5. P0 — Validate on CICIDS2017 benchmark (2.8M records)
6. P0 — Explicit paper comparison (AARF, AETHER, LLM Honeypot)
7. P1 — Feedback Agent (adaptation loop — makes agent claim defensible)
8. P1 — AR9271 wireless monitoring
9. P1 — Add 4 more features to ML vector (10-dim total)

## Writing Style
- Formal IEEE academic tone
- Every claim backed by experimental data
- Contribution framed as validated system, not just integration
- Include comparison tables, graphs, confusion matrices
- Use "agent-inspired" NOT "agentic AI" or "AI agents"
- Use "autonomous pipeline" NOT "AI system"
- Explicit differentiation from 3 closest papers in Related Work

## Ethical Framing
- All WiFi monitoring is PASSIVE (probe request capture)
- AR9271 used for DETECTION, not attack
- Honeypot captures attacker behavior for DEFENSE research
- All experiments in controlled lab environment
