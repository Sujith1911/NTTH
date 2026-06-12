import asyncio
from datetime import datetime, timedelta

from app.api import routes_topology
from app.firewall import nft_manager
from app.monitor import network_scanner


def test_stale_last_seen_is_not_current_presence():
    cutoff = datetime.utcnow() - timedelta(minutes=2)
    stale_last_seen = datetime.utcnow() - timedelta(hours=1)

    assert not routes_topology._is_recent(stale_last_seen, cutoff)


def test_recent_last_seen_is_present():
    cutoff = datetime.utcnow() - timedelta(minutes=2)
    recent_last_seen = datetime.utcnow() - timedelta(seconds=30)

    assert routes_topology._is_recent(recent_last_seen, cutoff)


def test_dnsmasq_lease_must_be_current():
    now_epoch = 2_000

    assert network_scanner._lease_is_current("0", now_epoch)
    assert network_scanner._lease_is_current("2001", now_epoch)
    assert not network_scanner._lease_is_current("1999", now_epoch)
    assert not network_scanner._lease_is_current("invalid", now_epoch)


def test_ssh_redirect_uses_gateway_cowrie_dnat(monkeypatch):
    commands = []
    rule = "ip saddr 192.168.4.177 tcp dport 22 dnat to 192.168.4.1:30022"

    async def fake_run_nft(*args):
        commands.append(args)
        if args[:4] == ("-a", "list", "chain", "ip"):
            return 0, f"{rule} # handle 42", ""
        return 0, "", ""

    monkeypatch.setattr(nft_manager, "_run_nft", fake_run_nft)
    monkeypatch.setattr(nft_manager.settings, "gateway_ip", "192.168.4.1")

    handle = asyncio.run(
        nft_manager.NFTManager().add_redirect(
            "192.168.4.177",
            src_port=22,
            dst_port=30022,
            persist=False,
        )
    )

    assert handle == "nat:42"
    assert (
        "add", "rule", "ip", "ntth_nat", "ntth_prerouting",
        "ip", "saddr", "192.168.4.177", "tcp", "dport", "22",
        "dnat", "to", "192.168.4.1:30022",
    ) in commands
