#!/usr/bin/env python3
"""Full cleanup: remove broadcast, stale devices, false-positive threats, reset risk."""
import sqlite3
import os

DB = os.path.join(os.path.dirname(__file__), "ntth.db")
conn = sqlite3.connect(DB)
c = conn.cursor()

print("=== BEFORE ===")
c.execute("SELECT ip_address, risk_score FROM devices ORDER BY ip_address")
for row in c.fetchall():
    print(f"  {row[0]:20s} risk={row[1]:.2f}")

# 1. Delete broadcast address (not a real device)
c.execute("DELETE FROM devices WHERE ip_address = '10.223.251.255'")
print(f"\n✅ Deleted broadcast 10.223.251.255: {c.rowcount} rows")

# 2. Delete stale device 10.223.251.112 (not live)
c.execute("DELETE FROM devices WHERE ip_address = '10.223.251.112'")
print(f"✅ Deleted stale 10.223.251.112: {c.rowcount} rows")

# 3. Reset risk for gateway and server
c.execute("UPDATE devices SET risk_score = 0.0 WHERE ip_address IN ('10.223.251.124', '10.223.251.241')")
print(f"✅ Reset risk for gateway+server: {c.rowcount} rows")

# 4. Delete all threat events from self IPs
SELF_IPS = ('10.223.251.241', '10.223.251.124', '10.223.251.255')
c.execute("DELETE FROM threat_events WHERE src_ip IN (?,?,?)", SELF_IPS)
print(f"✅ Deleted self-IP threats: {c.rowcount} rows")

# 5. Delete threats TO broadcast/multicast
c.execute("DELETE FROM threat_events WHERE dst_ip LIKE '224.%' OR dst_ip LIKE '%.255'")
print(f"✅ Deleted multicast/broadcast threats: {c.rowcount} rows")

# 6. Deactivate firewall rules for self IPs
for ip in SELF_IPS:
    c.execute("UPDATE firewall_rules SET is_active = 0 WHERE target_ip = ?", (ip,))
    if c.rowcount:
        print(f"✅ Deactivated firewall rules for {ip}: {c.rowcount}")

# 7. Delete threats from the broadcast device
c.execute("DELETE FROM threat_events WHERE src_ip = '10.223.251.255' OR dst_ip = '10.223.251.255'")
print(f"✅ Deleted broadcast threats: {c.rowcount} rows")

conn.commit()

print("\n=== AFTER ===")
c.execute("SELECT ip_address, risk_score, hostname FROM devices ORDER BY ip_address")
for row in c.fetchall():
    print(f"  {row[0]:20s} risk={row[1]:.2f} host={row[2] or '-'}")

c.execute("SELECT COUNT(*) FROM threat_events")
print(f"\nTotal remaining threats: {c.fetchone()[0]}")

conn.close()
print("\n✅ Full cleanup complete")
