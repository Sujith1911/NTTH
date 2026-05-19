from scapy.all import ARP, Ether, IP, TCP, Raw

from app.monitor.feature_extractor import extract_features


def test_extracts_http_form_fields():
    pkt = (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
        / IP(src="192.168.4.95", dst="93.184.216.34")
        / TCP(sport=50123, dport=80, flags="PA")
        / Raw(
            b"POST /login HTTP/1.1\r\n"
            b"Host: example.test\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"User-Agent: ntth-test\r\n\r\n"
            b"username=admin&password=secret"
        )
    )

    features = extract_features(pkt)

    assert features["http_method"] == "POST"
    assert features["http_host"] == "example.test"
    assert features["http_path"] == "/login"
    assert '"username": "admin"' in features["http_form_fields"]
    assert features["flow_id"].startswith("tcp|")


def test_extracts_tls_sni_from_client_hello_like_payload():
    sni = b"example.com"
    server_name_ext = (
        b"\x00\x00"
        + (len(sni) + 5).to_bytes(2, "big")
        + (len(sni) + 3).to_bytes(2, "big")
        + b"\x00"
        + len(sni).to_bytes(2, "big")
        + sni
    )
    body = (
        b"\x01\x00\x00\x00"
        + b"\x03\x03"
        + (b"\x00" * 32)
        + b"\x00"
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + len(server_name_ext).to_bytes(2, "big")
        + server_name_ext
    )
    payload = b"\x16\x03\x01" + len(body).to_bytes(2, "big") + body
    pkt = (
        Ether()
        / IP(src="192.168.4.95", dst="93.184.216.34")
        / TCP(sport=50123, dport=443, flags="PA")
        / Raw(payload)
    )

    features = extract_features(pkt)

    assert features["tls_sni"] == "example.com"
    assert features["tls_version"] == "0x0301"


def test_extracts_arp_request_features():
    pkt = (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.4.95", pdst="192.168.4.10")
    )

    features = extract_features(pkt)

    assert features["protocol"] == "arp"
    assert features["src_ip"] == "192.168.4.95"
    assert features["dst_ip"] == "192.168.4.10"
    assert features["arp_target_ip"] == "192.168.4.10"
    assert features["is_arp_request"] is True
    assert features["flow_id"] == "arp|192.168.4.95|192.168.4.10"
