#!/usr/bin/env python3
"""Clean up false-positive threat events from self-scanning and reset gateway risk."""
import sqlite3
import os

DB = os.path.join(os.path.dirname(__file__), "ntth.db")
conn = sqlite3.connect(DB)
c = conn.cursor()

SELF_IPS = ("10.223.251.241", "10.223.251.124")

# Show current state
c.execute("SELECT ip_address, risk_score, hostname FROM devices")
print("=== DEVICES ===")
for row in c.fetchall():
    print(f"  {row}")

# Count self-generated threats
c.execute("SELECT COUNT(*) FROM threat_events WHERE src_ip IN (?, ?)", SELF_IPS)
self_threats = c.fetchone()[0]
print(f"\nThreats from self/gateway: {self_threats}")

# Count multicast threats
c.execute("SELECT COUNT(*) FROM threat_events WHERE dst_ip LIKE '224.%' OR dst_ip LIKE '%.255'")
mc_threats = c.fetchone()[0]
print(f"Multicast/broadcast threats: {mc_threats}")

# Delete self-generated false positives
c.execute("DELETE FROM threat_events WHERE src_ip IN (?, ?)", SELF_IPS)
print(f"Deleted {c.rowcount} self-scan false positives")

# Delete multicast false positives
c.execute("DELETE FROM threat_events WHERE dst_ip LIKE '224.%' OR dst_ip LIKE '%.255'")
print(f"Deleted {c.rowcount} multicast false positives")

# Reset risk scores for gateway and server
for ip in SELF_IPS:
    c.execute("UPDATE devices SET risk_score = 0.0 WHERE ip_address = ?", (ip,))
    print(f"Reset risk for {ip}: {c.rowcount} rows")

# Deactivate firewall rules for self IPs
for ip in SELF_IPS:
    c.execute("UPDATE firewall_rules SET is_active = 0 WHERE target_ip = ?", (ip,))
    if c.rowcount:
        print(f"Deactivated {c.rowcount} firewall rules for {ip}")

conn.commit()

# Verify
c.execute("SELECT ip_address, risk_score FROM devices")
print("\n=== AFTER CLEANUP ===")
for row in c.fetchall():
    print(f"  {row}")

c.execute("SELECT COUNT(*) FROM threat_events")
print(f"\nTotal remaining threats: {c.fetchone()[0]}")

conn.close()
print("\n✅ Cleanup complete")
