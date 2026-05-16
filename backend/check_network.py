#!/usr/bin/env python3
"""Check what devices are in DB vs what's actually alive on the network."""
import sqlite3
import subprocess
import os

DB = os.path.join(os.path.dirname(__file__), "ntth.db")
conn = sqlite3.connect(DB)
c = conn.cursor()

print("=" * 60)
print("DEVICES IN DATABASE")
print("=" * 60)
c.execute("SELECT id, ip_address, hostname, mac_address, vendor, risk_score, open_ports FROM devices ORDER BY ip_address")
for row in c.fetchall():
    did, ip, host, mac, vendor, risk, ports = row
    print(f"  [{did}] {ip:20s} host={host or '-':15s} mac={mac or '-':18s} risk={risk:.2f} ports={ports or '[]'}")

print()
print("=" * 60)
print("LIVE HOSTS ON NETWORK (ping scan)")
print("=" * 60)

# Quick ping scan
try:
    out = subprocess.check_output(
        ["bash", "-c", "for i in $(seq 1 254); do (ping -c1 -W1 10.223.251.$i &>/dev/null && echo 10.223.251.$i) & done; wait"],
        text=True, timeout=30
    )
    live = sorted(out.strip().split('\n')) if out.strip() else []
    for ip in live:
        print(f"  ✅ {ip}")
    print(f"\nTotal live: {len(live)}")
except Exception as e:
    print(f"  Error: {e}")
    # Fallback: check ARP table
    print("\n  ARP table fallback:")
    try:
        out = subprocess.check_output(["arp", "-a"], text=True, timeout=5)
        for line in out.splitlines():
            if "10.223.251" in line:
                print(f"    {line.strip()}")
    except:
        pass

print()
print("=" * 60)
print("THREAT EVENTS SUMMARY")
print("=" * 60)
c.execute("SELECT src_ip, COUNT(*), MAX(risk_score) FROM threat_events GROUP BY src_ip ORDER BY COUNT(*) DESC LIMIT 15")
for row in c.fetchall():
    print(f"  {row[0]:20s} threats={row[1]:4d} max_risk={row[2]:.2f}")

c.execute("SELECT COUNT(*) FROM threat_events")
print(f"\nTotal threats: {c.fetchone()[0]}")

c.execute("SELECT COUNT(*) FROM captured_packets")
print(f"Total packets: {c.fetchone()[0]}")

conn.close()
