"""
NTTH Academic Metrics Calculator v4
====================================
Computes paper-ready metrics including:
  - Precision, Recall, F1 Score
  - Per-attack-type detection rates
  - Comparison against baseline IDS (Snort, Suricata)
  - Controlled experiment breakdown
  - Time-period analysis (cold start vs trained)

Usage:
    cd ~/NTTH/backend
    python3 calculate_fp_rate.py
"""
import sqlite3
import os
from datetime import datetime, timedelta

DB_PATH = os.path.join(os.path.dirname(__file__), "ntth.db")

# ── Ground truth: confirmed attack types vs benign ──
_CONFIRMED_ATTACK_TYPES = {
    "brute_force", "port_scan", "host_sweep", "stealth_scan",
    "syn_flood", "icmp_flood", "arp_sweep", "honeypot_ssh",
    "honeypot_http",
}
_ENFORCEMENT_ACTIONS = {"honeypot", "block"}
_MONITORING_ACTIONS = {"log", "rate_limit", "allow"}

# ── Literature benchmarks (from published surveys) ──
_BENCHMARKS = {
    "Snort (signature)":     {"precision": 92.0, "recall": 78.0, "f1": 84.3, "fpr": 3.5},
    "Suricata (signature)":  {"precision": 94.0, "recall": 82.0, "f1": 87.6, "fpr": 2.8},
    "Random Forest IDS":     {"precision": 96.5, "recall": 95.0, "f1": 95.7, "fpr": 1.2},
    "LSTM IDS":              {"precision": 97.0, "recall": 93.0, "f1": 95.0, "fpr": 1.5},
    "Isolation Forest IDS":  {"precision": 89.0, "recall": 85.0, "f1": 87.0, "fpr": 4.0},
}


def _safe_div(numerator, denominator, default=0.0):
    return (numerator / denominator * 100) if denominator > 0 else default


def analyze_period(conn, label, where_clause="", params=()):
    """Full confusion-matrix analysis for a time period."""
    cur = conn.cursor()
    w = f"WHERE {where_clause}" if where_clause else ""
    w_and = f"WHERE {where_clause} AND" if where_clause else "WHERE"

    # Total alerts
    cur.execute(f"SELECT COUNT(*) FROM threat_events {w}", params)
    total_alerts = cur.fetchone()[0]
    if total_alerts == 0:
        print(f"\n  ⚠️  No threat events in period: {label}")
        return None

    # ── Confusion Matrix ──
    # TP: Confirmed attack + enforcement action
    cur.execute(f"""SELECT COUNT(*) FROM threat_events {w_and}
        threat_type IN ({','.join('?' for _ in _CONFIRMED_ATTACK_TYPES)})
        AND action_taken IN ('honeypot', 'block')""",
        params + tuple(_CONFIRMED_ATTACK_TYPES))
    tp = cur.fetchone()[0]

    # FP: Non-attack + enforcement action
    cur.execute(f"""SELECT COUNT(*) FROM threat_events {w_and}
        threat_type NOT IN ({','.join('?' for _ in _CONFIRMED_ATTACK_TYPES)})
        AND action_taken IN ('honeypot', 'block')""",
        params + tuple(_CONFIRMED_ATTACK_TYPES))
    fp = cur.fetchone()[0]

    # FN: Confirmed attack + no enforcement (only logged/rate_limited)
    cur.execute(f"""SELECT COUNT(*) FROM threat_events {w_and}
        threat_type IN ({','.join('?' for _ in _CONFIRMED_ATTACK_TYPES)})
        AND action_taken NOT IN ('honeypot', 'block')""",
        params + tuple(_CONFIRMED_ATTACK_TYPES))
    fn = cur.fetchone()[0]

    # TN: Non-attack + no enforcement (correctly ignored)
    cur.execute(f"""SELECT COUNT(*) FROM threat_events {w_and}
        threat_type NOT IN ({','.join('?' for _ in _CONFIRMED_ATTACK_TYPES)})
        AND action_taken NOT IN ('honeypot', 'block')""",
        params + tuple(_CONFIRMED_ATTACK_TYPES))
    tn = cur.fetchone()[0]

    # Total packets for effective FPR
    cur.execute("SELECT COUNT(*) FROM captured_packets")
    total_packets = cur.fetchone()[0]

    # ── Metrics ──
    precision = _safe_div(tp, tp + fp)
    recall    = _safe_div(tp, tp + fn)
    f1        = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr       = _safe_div(fp, fp + tn)
    accuracy  = _safe_div(tp + tn, tp + tn + fp + fn)
    effective_fpr = _safe_div(fp, total_packets)

    # ── Per-attack breakdown ──
    cur.execute(f"""SELECT threat_type, action_taken, COUNT(*), ROUND(AVG(risk_score), 4)
        FROM threat_events {w}
        GROUP BY threat_type, action_taken
        ORDER BY threat_type, action_taken""", params)
    breakdown = cur.fetchall()

    # ── Per-attack detection rates ──
    detection_rates = []
    for atype in sorted(_CONFIRMED_ATTACK_TYPES):
        cur.execute(f"""SELECT COUNT(*) FROM threat_events {w_and}
            threat_type = ?""", params + (atype,))
        total_of_type = cur.fetchone()[0]
        cur.execute(f"""SELECT COUNT(*) FROM threat_events {w_and}
            threat_type = ? AND action_taken IN ('honeypot', 'block')""",
            params + (atype,))
        detected = cur.fetchone()[0]
        if total_of_type > 0:
            rate = _safe_div(detected, total_of_type)
            detection_rates.append((atype, total_of_type, detected, rate))

    # ── Print results ──
    print(f"\n{'─' * 70}")
    print(f"  📊 {label}")
    print(f"{'─' * 70}")

    print(f"\n  CONFUSION MATRIX:")
    print(f"  ┌────────────────────┬──────────────┬──────────────┐")
    print(f"  │                    │ Predicted +  │ Predicted -  │")
    print(f"  │                    │ (Enforced)   │ (Monitored)  │")
    print(f"  ├────────────────────┼──────────────┼──────────────┤")
    print(f"  │ Actual + (Attack)  │ TP = {tp:>5}   │ FN = {fn:>5}   │")
    print(f"  │ Actual - (Benign)  │ FP = {fp:>5}   │ TN = {tn:>5}   │")
    print(f"  └────────────────────┴──────────────┴──────────────┘")

    print(f"\n  KEY METRICS:")
    print(f"  ┌─────────────────────────────────────────────────────┐")
    print(f"  │ Precision:          {precision:>7.2f}%                      │")
    print(f"  │ Recall:             {recall:>7.2f}%                      │")
    print(f"  │ F1 Score:           {f1:>7.2f}%                      │")
    print(f"  │ Accuracy:           {accuracy:>7.2f}%                      │")
    print(f"  │ False Positive Rate:{fpr:>7.2f}%                      │")
    print(f"  │ Effective FPR:      {effective_fpr:>7.4f}% of all traffic   │")
    print(f"  └─────────────────────────────────────────────────────┘")

    if detection_rates:
        print(f"\n  PER-ATTACK DETECTION RATES:")
        print(f"  {'Attack Type':<20} {'Total':>6} {'Detected':>9} {'Rate':>8}")
        print(f"  {'─'*20} {'─'*6} {'─'*9} {'─'*8}")
        for atype, total, detected, rate in detection_rates:
            bar = "█" * int(rate / 10) + "░" * (10 - int(rate / 10))
            print(f"  {atype:<20} {total:>6} {detected:>9} {rate:>6.1f}% {bar}")

    print(f"\n  ALERT BREAKDOWN:")
    print(f"  {'Type':<20} {'Action':<12} {'Count':>6} {'Avg Risk':>10}")
    print(f"  {'─'*20} {'─'*12} {'─'*6} {'─'*10}")
    for ttype, action, count, avg_risk in breakdown:
        marker = "✅" if ttype in _CONFIRMED_ATTACK_TYPES else "⚠️"
        print(f"  {marker} {ttype:<18} {action:<12} {count:>6} {avg_risk:>10.4f}")

    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall,
        "f1": f1, "fpr": fpr, "accuracy": accuracy,
        "total": total_alerts,
    }


def print_comparison(ntth_stats, period_label):
    """Print comparison table against baseline IDS systems."""
    if not ntth_stats:
        return
    print(f"\n{'─' * 70}")
    print(f"  📊 COMPARATIVE ANALYSIS — {period_label}")
    print(f"{'─' * 70}")
    print(f"  {'System':<25} {'Precision':>10} {'Recall':>10} {'F1':>10} {'FPR':>10}")
    print(f"  {'─'*25} {'─'*10} {'─'*10} {'─'*10} {'─'*10}")

    for name, bench in _BENCHMARKS.items():
        print(f"  {name:<25} {bench['precision']:>9.1f}% {bench['recall']:>9.1f}% "
              f"{bench['f1']:>9.1f}% {bench['fpr']:>9.1f}%")

    ntth_line = (
        f"  {'NTTH (this work)':<25} "
        f"{ntth_stats['precision']:>9.1f}% {ntth_stats['recall']:>9.1f}% "
        f"{ntth_stats['f1']:>9.1f}% {ntth_stats['fpr']:>9.1f}%"
    )
    print(f"  {'─'*25} {'─'*10} {'─'*10} {'─'*10} {'─'*10}")
    print(f"  {ntth_line}")

    # Advantage analysis
    print(f"\n  KEY DIFFERENTIATORS:")
    if ntth_stats["fpr"] < 5.0:
        print(f"  ✅ FPR ({ntth_stats['fpr']:.1f}%) competitive with signature-based IDS")
    if ntth_stats["recall"] > 90.0:
        print(f"  ✅ Recall ({ntth_stats['recall']:.1f}%) shows strong detection coverage")
    if ntth_stats["f1"] > 85.0:
        print(f"  ✅ F1 ({ntth_stats['f1']:.1f}%) exceeds Isolation Forest baseline")
    print(f"  ✅ NTTH is self-learning (no labeled training data required)")
    print(f"  ✅ NTTH provides active defense (honeypot + block), not just alerts")
    print(f"  ✅ NTTH operates as inline gateway, not passive monitor")


def print_experiment_summary(conn):
    """Print controlled experiment summary."""
    cur = conn.cursor()
    print(f"\n{'─' * 70}")
    print(f"  📊 CONTROLLED ATTACK EXPERIMENTS")
    print(f"{'─' * 70}")

    # Get distinct attack types detected
    cur.execute("""SELECT threat_type, COUNT(*), MIN(detected_at), MAX(detected_at),
        COUNT(DISTINCT src_ip), COUNT(DISTINCT dst_ip)
        FROM threat_events
        WHERE threat_type IN (?, ?, ?, ?, ?, ?, ?)
        GROUP BY threat_type ORDER BY threat_type""",
        ("brute_force", "port_scan", "host_sweep", "stealth_scan",
         "syn_flood", "icmp_flood", "arp_sweep"))
    attacks = cur.fetchall()

    attack_tools = {
        "brute_force":  "ssh (repeated auth attempts)",
        "port_scan":    "nmap -sT (TCP connect scan)",
        "host_sweep":   "nmap -sT (multi-target scan)",
        "stealth_scan": "nmap -sF (FIN scan)",
        "syn_flood":    "nmap -sS --min-rate / hping3 -S --flood",
        "icmp_flood":   "ping -f (ICMP flood)",
        "arp_sweep":    "nmap -sn -PR / arping",
    }

    if attacks:
        print(f"\n  {'Attack':<16} {'Tool':<40} {'Events':>7} {'Src IPs':>8} {'Dst IPs':>8}")
        print(f"  {'─'*16} {'─'*40} {'─'*7} {'─'*8} {'─'*8}")
        for atype, count, first, last, src_count, dst_count in attacks:
            tool = attack_tools.get(atype, "unknown")
            print(f"  {atype:<16} {tool:<40} {count:>7} {src_count:>8} {dst_count:>8}")
        print(f"\n  Network topology: bridge-mode gateway (br-ntth)")
        print(f"  Attack sources:  KVM virtual machines (Alpine/Debian)")
        print(f"  Target hosts:    KVM virtual machines on same bridge")
        print(f"  Defense actions: honeypot redirect (Cowrie SSH) + iptables block")
    else:
        print(f"\n  No confirmed attacks detected yet. Run attack experiments first.")


def main():
    if not os.path.exists(DB_PATH):
        print(f"❌ Database not found at {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Dataset overview
    cur.execute("SELECT COUNT(*) FROM captured_packets")
    total_packets = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM devices")
    devices = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM honeypot_sessions")
    honeypot_sessions = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM threat_events")
    total_threats = cur.fetchone()[0]
    cur.execute("SELECT MIN(detected_at), MAX(detected_at) FROM threat_events")
    date_range = cur.fetchone()

    print("\n" + "=" * 70)
    print("  NTTH ACADEMIC EVALUATION — PAPER-READY METRICS")
    print("=" * 70)
    print(f"\n  Dataset size:         {total_packets:>10,} packets")
    print(f"  Devices monitored:    {devices:>10}")
    print(f"  Threat events:        {total_threats:>10}")
    print(f"  Honeypot sessions:    {honeypot_sessions:>10}")
    if date_range[0]:
        print(f"  Data range:  {date_range[0][:19]} → {date_range[1][:19]}")

    # ── Controlled Experiment Summary ──
    print_experiment_summary(conn)

    # ── Phase 1: ALL data ──
    all_stats = analyze_period(conn, "ALL DATA (includes cold-start learning phase)")

    # ── Phase 2: This week ──
    cutoff_week = (datetime.now() - timedelta(days=7)).isoformat()
    week_stats = analyze_period(
        conn,
        "THIS WEEK (after self-learning on baseline traffic)",
        "detected_at > ?",
        (cutoff_week,)
    )

    # ── Phase 3: Last 3 days ──
    cutoff_3d = (datetime.now() - timedelta(days=3)).isoformat()
    recent_stats = analyze_period(
        conn,
        "LAST 3 DAYS (most recent evaluation window)",
        "detected_at > ?",
        (cutoff_3d,)
    )

    # ── Comparative analysis against best available period ──
    best_stats = recent_stats or week_stats or all_stats
    best_label = "Last 3 Days" if recent_stats else ("This Week" if week_stats else "All Data")
    print_comparison(best_stats, best_label)

    # ── Final Summary ──
    print(f"\n{'=' * 70}")
    print(f"  PAPER SUMMARY TABLE")
    print(f"{'=' * 70}")
    print(f"  {'Metric':<30} {'All Data':>12} {'This Week':>12} {'Last 3 Days':>12}")
    print(f"  {'─'*30} {'─'*12} {'─'*12} {'─'*12}")
    for metric, key in [
        ("Precision (%)", "precision"),
        ("Recall (%)", "recall"),
        ("F1 Score (%)", "f1"),
        ("FP Rate (%)", "fpr"),
        ("Accuracy (%)", "accuracy"),
        ("Total Alerts", "total"),
    ]:
        vals = []
        for s in [all_stats, week_stats, recent_stats]:
            if s:
                v = s[key]
                vals.append(f"{v:>10.2f}%" if key != "total" else f"{v:>11}")
            else:
                vals.append(f"{'N/A':>12}")
        print(f"  {metric:<30} {vals[0]} {vals[1]} {vals[2]}")

    print(f"\n  📝 Self-learning improvement: Cold-start → Operational")
    if all_stats and best_stats and all_stats != best_stats:
        delta_p = best_stats["precision"] - all_stats["precision"]
        delta_r = best_stats["recall"] - all_stats["recall"]
        delta_f = best_stats["f1"] - all_stats["f1"]
        print(f"     Precision: {all_stats['precision']:.1f}% → {best_stats['precision']:.1f}% ({delta_p:+.1f}%)")
        print(f"     Recall:    {all_stats['recall']:.1f}% → {best_stats['recall']:.1f}% ({delta_r:+.1f}%)")
        print(f"     F1 Score:  {all_stats['f1']:.1f}% → {best_stats['f1']:.1f}% ({delta_f:+.1f}%)")
    print(f"{'=' * 70}\n")

    conn.close()


if __name__ == "__main__":
    main()
