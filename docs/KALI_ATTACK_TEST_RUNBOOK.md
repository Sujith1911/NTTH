# Kali Attack Test Runbook

This runbook is for real testing only. Built-in threat simulation is disabled in the live app, so every event you see should come from real network traffic or real honeypot interaction.

## Goal

Validate that:

- real assets appear under `Devices`
- real attacks create entries under `Threat Map`
- containment creates active firewall redirects
- diverted attacker activity appears under `Honeypot`
- all of that is stored in PostgreSQL and streamed live to the Flutter dashboard

## Before You Start

Make sure the app is running:

- Flutter web UI: `http://127.0.0.1:8000/`
- Backend API: `http://127.0.0.1:8000/api/v1/system/health`

Log in to the UI and confirm:

- `System` shows `Firewall mode: enforcing`
- `System` shows `Honeypot: Ready for diversion`
- `Devices` shows only your real subnet assets
- `Threat Map`, `Firewall`, and `Honeypot` are empty before testing if you want a clean baseline

Recommended test setup:

- Defender machine: the Windows host running this app
- Attacker machine: Kali Linux in `Bridged` mode first
- Optional second pass: Kali in `NAT` mode to observe how source identity changes

Important note:

- `Bridged` mode is best for realistic LAN visibility
- `NAT` mode can still be detected, but the visible source may be the NAT-facing address, not the Kali guest's original LAN identity

## Step 1: Baseline the Defender UI

Open these screens side by side if possible:

- `Dashboard`
- `Devices`
- `Threat Map`
- `Firewall`
- `Honeypot`
- `System`

Expected baseline:

- `Devices` contains only your real asset inventory
- `Threat Map` shows `0`
- `Firewall` shows `0 active rules`
- `Honeypot` shows `0 sessions`

## Step 2: Discover Targets from Kali

On Kali, find the target subnet:

```bash
ip a
ip route
```

Confirm the defender IP from the app:

- `Devices` or `Topology` should show the NTTH host
- your current live subnet in this deployment is expected to be `192.168.1.0/24`

## Step 3: Scan the Network

Run a ping sweep:

```bash
nmap -sn 192.168.1.0/24
```

Then run a SYN scan:

```bash
sudo nmap -sS -Pn 192.168.1.39
```

Then a broader service scan:

```bash
sudo nmap -sS -sV -O -Pn 192.168.1.39
```

Expected defender-side behavior:

- `Threat Map` should show a new incident from the Kali source IP
- `Dashboard` should increment `Live incidents`
- `Firewall` should show containment attempts and then active redirects
- `Devices` should keep showing only protected internal assets, not your public or attacker IP as a device row

## Step 4: Trigger SSH Honeypot Diversion

Probe SSH repeatedly:

```bash
nc -vz 192.168.1.39 22
```

Then attempt SSH:

```bash
ssh root@192.168.1.39 -p 22
```

Try a few credentials when prompted:

- `root / root`
- `admin / admin`
- `user / password`

If diversion is active, you should be interacting with Cowrie rather than a real host.

Expected defender-side behavior:

- `Firewall` shows active redirect rules
- `Honeypot` shows a new SSH session
- usernames/passwords tried appear in session details
- commands entered in the SSH session appear under `Commands`

## Step 5: Generate Command Capture

Once inside the diverted SSH session, type commands like:

```bash
whoami
uname -a
pwd
ls
cat /etc/passwd
ip a
ifconfig
netstat -tulpn
```

Expected defender-side behavior:

- `Honeypot` updates live
- the session row expands with command history
- the source IP, approximate location, ASN/org, and session timing are stored in the database

## Step 6: Trigger HTTP Honeypot Diversion

Run HTTP probes from Kali:

```bash
curl -v http://192.168.1.39/
curl -v http://192.168.1.39/login
curl -v http://192.168.1.39/admin
nikto -h http://192.168.1.39
```

Expected defender-side behavior:

- `Threat Map` gets new incidents or updated threat history
- `Firewall` shows redirect activity for HTTP
- `Honeypot` shows HTTP sessions with method, path, and body details

## Step 7: Brute Force Test

Use Hydra carefully against the defender IP:

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.39 -t 4 -f
```

Expected defender-side behavior:

- risk rises quickly
- multiple containment events may appear
- the honeypot should capture attempted usernames/passwords

## Step 8: Validate from the Database

From the defender machine:

```powershell
docker exec ntth_postgres psql -U ntth_user -d ntth -c "select src_ip, threat_type, risk_score, action_taken, detected_at from threat_events order by detected_at desc limit 20;"
docker exec ntth_postgres psql -U ntth_user -d ntth -c "select target_ip, rule_type, nft_handle, is_active, created_at from firewall_rules order by created_at desc limit 20;"
docker exec ntth_postgres psql -U ntth_user -d ntth -c "select attacker_ip, honeypot_type, username_tried, commands_run, started_at from honeypot_sessions order by started_at desc limit 20;"
```

Expected result:

- `threat_events` contains the attack records
- `firewall_rules` contains containment rules
- `honeypot_sessions` contains diverted session data and commands

## What to Watch in the Flutter UI

`Dashboard`

- `Live incidents` should rise
- `Critical responses` should rise for more aggressive detections
- `Honeypot redirects` should rise when traffic is diverted

`Devices`

- only internal protected assets should be listed
- attacked asset risk should increase

`Threat Map`

- should show source IP, victim IP, response mode, and approximate source enrichment

`Firewall`

- should show attempted containment and active rules separately

`Honeypot`

- should show diverted sessions
- for SSH, commands should appear live
- for HTTP, path/method/body should appear in the session details

`System`

- should remain `Firewall: enforcing`
- should remain `Honeypot: Ready for diversion`

## Bridged vs NAT Notes

Bridged mode:

- best choice for realistic testing
- Kali should appear as its own LAN IP

NAT mode:

- the source may appear as a translated address
- this is normal and reflects the network path you are testing through
- exact attacker identity is not guaranteed when NAT is involved

## If You Do Not See Events

Check these in order:

1. `System` page says `Firewall: enforcing`
2. `System` page says `Honeypot: Ready for diversion`
3. `Devices` page shows the defender subnet correctly
4. Kali can actually reach the defender IP
5. You are using `Bridged` networking for the clearest first test
6. `docker logs ntth_backend --tail 200`
7. `docker exec ntth_backend sh -lc "nft list ruleset"`

## Recommended First Real Test Sequence

1. `nmap -sn 192.168.1.0/24`
2. `sudo nmap -sS -Pn 192.168.1.39`
3. `ssh root@192.168.1.39 -p 22`
4. type `whoami`, `uname -a`, `ls`, `cat /etc/passwd`
5. inspect `Dashboard`, `Threat Map`, `Firewall`, and `Honeypot`

That gives you the clearest first proof that discovery, detection, containment, deception, persistence, and UI streaming are all working together.
