# Exact Ubuntu Gateway Commands For Kali And Victim

This is the command-level walkthrough for the real gateway lab.

## 1. Target Lab Layout

### Ubuntu Gateway

- upstream interface: `enp0s3`
- protected interface: `enp0s8`

### Kali

- attacker-side IP: `10.10.10.20/24`
- gateway: `10.10.10.1`

### Victim

- protected-side IP: `192.168.50.10/24`
- gateway: `192.168.50.1`

### Ubuntu

- attacker side IP: `10.10.10.1/24`
- protected side IP: `192.168.50.1/24`

## 2. Ubuntu Netplan Example

Edit:

```bash
sudo nano /etc/netplan/01-netcfg.yaml
```

Use:

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:
      dhcp4: false
      addresses:
        - 10.10.10.1/24
    enp0s8:
      dhcp4: false
      addresses:
        - 192.168.50.1/24
```

Apply:

```bash
sudo netplan apply
ip a
ip route
```

## 3. Ubuntu Enable Routing

```bash
sudo sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

## 4. Ubuntu NAT Rules

```bash
sudo iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE
sudo iptables -A FORWARD -i enp0s3 -o enp0s8 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i enp0s8 -o enp0s3 -j ACCEPT
```

## 5. Victim Static IP Commands

If the victim is Linux and you want a temporary config:

```bash
sudo ip addr flush dev enp0s3
sudo ip addr add 192.168.50.10/24 dev enp0s3
sudo ip route add default via 192.168.50.1
ip a
ip route
```

Then install SSH:

```bash
sudo apt update
sudo apt install -y openssh-server
sudo systemctl enable ssh
sudo systemctl start ssh
sudo systemctl status ssh
```

## 6. Kali Static IP Commands

Temporary config:

```bash
sudo ip addr flush dev eth0
sudo ip addr add 10.10.10.20/24 dev eth0
sudo ip route add default via 10.10.10.1
ip a
ip route
```

## 7. Connectivity Checks

From Kali:

```bash
ping 10.10.10.1
ping 192.168.50.10
```

From Victim:

```bash
ping 192.168.50.1
```

## 8. Test Real Victim Access First

From Kali:

```bash
ssh <victim-user>@192.168.50.10
```

At this stage it should reach the real victim.

## 9. Start The App On Ubuntu

```bash
cd ~/projects/No\ Time\ To\ Hack/backend
docker compose up -d --build
```

Optional migration step:

```bash
alembic upgrade head
```

## 10. Open The Dashboard

From Kali browser or another reachable machine:

```text
http://10.10.10.1:8000
```

## 11. Attack Commands From Kali

### Port scan

```bash
nmap -sS -Pn 192.168.50.10
```

### SSH attack

```bash
ssh root@192.168.50.10
```

### Commands once redirected into Cowrie

```bash
whoami
uname -a
ls
pwd
exit
```

## 12. What To Check In The UI

### Threat Map

- attacker `10.10.10.20`
- victim `192.168.50.10`

### Firewall

- redirect rule for attacker to victim flow

### Honeypot

- victim IP
- credentials
- commands

## 13. Permanent Netplan Examples For Kali Or Victim

If those are Ubuntu-based systems, use netplan.

### Victim example

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:
      dhcp4: false
      addresses:
        - 192.168.50.10/24
      routes:
        - to: default
          via: 192.168.50.1
```

### Kali or attacker-side Linux example

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: false
      addresses:
        - 10.10.10.20/24
      routes:
        - to: default
          via: 10.10.10.1
```
