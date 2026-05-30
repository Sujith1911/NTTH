"""
IOC (Indicator of Compromise) extractor — scans honeypot session data
for URLs, IP addresses, domains, and file hashes.

Used by session_logger and cowrie_watcher to enrich threat intelligence
without relying on external threat feeds.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from app.core.logger import get_logger

log = get_logger("ioc_extractor")

# ── Patterns ─────────────────────────────────────────────────────────────────

_URL_RE = re.compile(
    r"(?:https?|ftp)://[^\s\"'<>]+",
    re.IGNORECASE,
)

_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|xyz|top|tk|ml|ga|cf|info|biz|cc|pw|sh|me|co)\b",
    re.IGNORECASE,
)

# Common shell download commands
_DOWNLOAD_CMD_RE = re.compile(
    r"\b(?:wget|curl|fetch|tftp|scp)\s+[^\s;|&]+",
    re.IGNORECASE,
)

# SHA256 / MD5 hashes (sometimes appear in malware commands)
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{32}\b")

# Suspicious command patterns
_SUSPICIOUS_CMD_PATTERNS = [
    re.compile(r"\brm\s+-rf\b", re.IGNORECASE),
    re.compile(r"\bchmod\s+[0-7]*7[0-7]*\b"),
    re.compile(r"\b/tmp/[^\s]+", re.IGNORECASE),
    re.compile(r"\bnc\s+-[lep]+", re.IGNORECASE),
    re.compile(r"\bpython[23]?\s+-c\b", re.IGNORECASE),
    re.compile(r"\bbase64\s+-d\b", re.IGNORECASE),
    re.compile(r"\bcrontab\b", re.IGNORECASE),
    re.compile(r"\b/dev/tcp/", re.IGNORECASE),
]

# IPs to exclude (private, loopback, etc.)
_PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                     "172.30.", "172.31.", "192.168.", "127.", "0.")


def _is_private_ip(ip: str) -> bool:
    return any(ip.startswith(prefix) for prefix in _PRIVATE_PREFIXES)


# ── IOC storage ──────────────────────────────────────────────────────────────

@dataclass
class IOCEntry:
    """A single extracted indicator of compromise."""
    ioc_type: str           # url, ip, domain, hash, download_cmd, suspicious_cmd
    value: str
    source_ip: str          # Attacker IP
    honeypot_type: str      # ssh, http, multi
    first_seen: str
    last_seen: str
    count: int = 1
    context: str = ""       # Surrounding command or session data


_ioc_store: dict[str, IOCEntry] = {}
_MAX_IOCS = 2000


def _ioc_key(ioc_type: str, value: str) -> str:
    return f"{ioc_type}:{value.lower().strip()}"


def _store_ioc(
    ioc_type: str,
    value: str,
    source_ip: str,
    honeypot_type: str,
    context: str = "",
) -> None:
    """Store or update an IOC entry."""
    key = _ioc_key(ioc_type, value)
    now = datetime.utcnow().isoformat()

    if key in _ioc_store:
        entry = _ioc_store[key]
        entry.count += 1
        entry.last_seen = now
        return

    if len(_ioc_store) >= _MAX_IOCS:
        # Evict oldest entry
        oldest_key = min(_ioc_store, key=lambda k: _ioc_store[k].last_seen)
        del _ioc_store[oldest_key]

    _ioc_store[key] = IOCEntry(
        ioc_type=ioc_type,
        value=value.strip(),
        source_ip=source_ip,
        honeypot_type=honeypot_type,
        first_seen=now,
        last_seen=now,
        context=context[:500],
    )


# ── Public API ───────────────────────────────────────────────────────────────

def extract_from_session(
    *,
    attacker_ip: str,
    honeypot_type: str,
    commands: Optional[str] = None,
    data_received: Optional[str] = None,
) -> list[dict]:
    """
    Extract IOCs from honeypot session data.

    Parameters:
        attacker_ip: The attacker's IP address
        honeypot_type: 'ssh', 'http', or protocol name
        commands: Raw command text (Cowrie input or multi-honeypot captured data)
        data_received: Raw data received from attacker

    Returns:
        List of extracted IOC dicts
    """
    text = " ".join(filter(None, [commands, data_received]))
    if not text or len(text) < 3:
        return []

    extracted: list[dict] = []

    # Extract URLs
    for match in _URL_RE.findall(text):
        _store_ioc("url", match, attacker_ip, honeypot_type, text[:200])
        extracted.append({"type": "url", "value": match})

    # Extract download commands
    for match in _DOWNLOAD_CMD_RE.findall(text):
        _store_ioc("download_cmd", match, attacker_ip, honeypot_type, text[:200])
        extracted.append({"type": "download_cmd", "value": match})

    # Extract IPs (exclude private)
    for match in _IP_RE.findall(text):
        if not _is_private_ip(match):
            _store_ioc("ip", match, attacker_ip, honeypot_type, text[:200])
            extracted.append({"type": "ip", "value": match})

    # Extract domains
    for match in _DOMAIN_RE.findall(text):
        _store_ioc("domain", match, attacker_ip, honeypot_type, text[:200])
        extracted.append({"type": "domain", "value": match})

    # Extract hashes
    for match in _HASH_RE.findall(text):
        _store_ioc("hash", match, attacker_ip, honeypot_type, text[:200])
        extracted.append({"type": "hash", "value": match})

    # Detect suspicious command patterns
    for pattern in _SUSPICIOUS_CMD_PATTERNS:
        for match in pattern.findall(text):
            _store_ioc("suspicious_cmd", match, attacker_ip, honeypot_type, text[:200])
            extracted.append({"type": "suspicious_cmd", "value": match})

    if extracted:
        log.info(
            "ioc_extractor.extracted",
            attacker_ip=attacker_ip,
            honeypot_type=honeypot_type,
            count=len(extracted),
            types=[e["type"] for e in extracted],
        )

    return extracted


def get_all_iocs(limit: int = 200) -> list[dict]:
    """Return all stored IOCs, most recent first."""
    entries = sorted(
        _ioc_store.values(),
        key=lambda e: e.last_seen,
        reverse=True,
    )[:limit]
    return [
        {
            "ioc_type": e.ioc_type,
            "value": e.value,
            "source_ip": e.source_ip,
            "honeypot_type": e.honeypot_type,
            "first_seen": e.first_seen,
            "last_seen": e.last_seen,
            "count": e.count,
            "context": e.context,
        }
        for e in entries
    ]


def get_ioc_summary() -> dict:
    """Return summary stats of IOC collection."""
    type_counts: dict[str, int] = {}
    for entry in _ioc_store.values():
        type_counts[entry.ioc_type] = type_counts.get(entry.ioc_type, 0) + 1
    return {
        "total_iocs": len(_ioc_store),
        "by_type": type_counts,
        "unique_source_ips": len({e.source_ip for e in _ioc_store.values()}),
    }


def get_iocs_by_ip(attacker_ip: str) -> list[dict]:
    """Return IOCs associated with a specific attacker IP."""
    return [
        {
            "ioc_type": e.ioc_type,
            "value": e.value,
            "first_seen": e.first_seen,
            "last_seen": e.last_seen,
            "count": e.count,
            "context": e.context,
        }
        for e in _ioc_store.values()
        if e.source_ip == attacker_ip
    ]
