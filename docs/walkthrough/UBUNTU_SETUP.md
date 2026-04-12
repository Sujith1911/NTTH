# Ubuntu Setup

This is the Ubuntu gateway setup for the real lab model.

## Goal

Ubuntu should become:

- app host
- packet capture host
- firewall enforcement point
- honeypot host
- gateway for protected devices

## Recommended VM Specs

- 4 vCPU
- 8 GB RAM
- 40 GB disk
- 2 NICs

## VirtualBox Network Model

### Adapter 1

- upstream
- use `NAT` or `Bridged Adapter`

### Adapter 2

- protected subnet
- use `Internal Network`
- example name: `PROTECTED_NET`

## Base Packages

```bash
sudo apt update
sudo apt upgrade -y
sudo apt autoremove -y
sudo apt install -y curl wget git unzip net-tools vim htop python3 python3-pip python3-venv docker.io docker-compose-plugin nftables openssh-server postgresql-client
```

## Enable Services

```bash
sudo systemctl enable docker
sudo systemctl start docker
sudo systemctl enable ssh
sudo systemctl start ssh
sudo systemctl enable nftables
sudo systemctl start nftables
```

## Find Interface Names

```bash
ip a
ip route
```

Example:

- `enp0s3` upstream
- `enp0s8` protected side

## Netplan Example

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
      dhcp4: true
    enp0s8:
      dhcp4: false
      addresses:
        - 192.168.50.1/24
```

Apply:

```bash
sudo netplan apply
```

## Enable Routing

```bash
sudo sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

## Add NAT For Protected Devices

```bash
sudo iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE
sudo iptables -A FORWARD -i enp0s3 -o enp0s8 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i enp0s8 -o enp0s3 -j ACCEPT
sudo apt install -y iptables-persistent
sudo netfilter-persistent save
```

## Copy The Project

Create a workspace:

```bash
mkdir -p ~/projects
cd ~/projects
```

Then copy the repo there and run:

```bash
cd ~/projects/No\ Time\ To\ Hack/backend
docker compose up -d --build
```

## Verify

```bash
docker ps
docker compose logs backend
docker compose logs cowrie
docker compose logs postgres
```

## Access

Open:

```text
http://<ubuntu-ip>:8000
```
