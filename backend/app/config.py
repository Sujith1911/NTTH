"""
Application configuration — reads from .env file.
All settings have sensible defaults for local development (SQLite, no GeoIP).
"""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── App ───────────────────────────────────────────────────────
    app_name: str = "NO TIME TO HACK"
    app_version: str = "1.0.0"
    environment: Literal["development", "production"] = "development"
    debug: bool = True

    # ── Security ──────────────────────────────────────────────────
    secret_key: str = "dev-secret-change-in-production-please"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    refresh_token_expire_days: int = 7

    # ── Admin seed ────────────────────────────────────────────────
    admin_username: str = "admin"
    admin_password: str = "changeme"

    # ── Database ──────────────────────────────────────────────────
    # In dev mode defaults to SQLite; in prod set DATABASE_URL env var.
    database_url: str = "sqlite+aiosqlite:///./ntth.db"

    # ── Network ───────────────────────────────────────────────────
    network_interface: str = "eth0"
    gateway_ip: str = "192.168.1.1"  # NEVER block this IP
    server_display_ip: str = ""
    scan_subnet: str = ""
    device_scan_interval_seconds: int = 60
    ignored_monitor_cidrs: list[str] = [
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
    ]

    # ── GeoIP ────────────────────────────────────────────────────
    geoip_db_path: str = "./geoip/GeoLite2-City.mmdb"
    geoip_asn_db_path: str = "./geoip/GeoLite2-ASN.mmdb"

    # ── IDS / Risk thresholds ─────────────────────────────────────
    risk_log_threshold: float = 0.4
    risk_rate_limit_threshold: float = 0.7
    risk_honeypot_threshold: float = 0.85
    risk_block_threshold: float = 0.95

    # ── Rule engine ───────────────────────────────────────────────
    port_scan_window_seconds: int = 10
    port_scan_unique_ports: int = 15
    syn_flood_per_second: int = 200
    brute_force_window_seconds: int = 60
    brute_force_attempts: int = 10

    # ── Firewall ──────────────────────────────────────────────────
    nft_table: str = "inet ntth_filter"
    nft_chain: str = "ntth_input"
    firewall_enabled: bool = True
    firewall_rule_ttl_seconds: int = 3600  # 1 hour default TTL
    cowrie_redirect_port: int = 2222

    event_bus_queue_size: int = 5000

    # ── Honeypot ─────────────────────────────────────────────────
    cowrie_container_name: str = "ntth_cowrie"
    cowrie_log_path: str = "/cowrie/var/log/cowrie/cowrie.json"
    http_honeypot_port: int = 8888
    http_honeypot_host: str = "0.0.0.0"

    # ── Logging ───────────────────────────────────────────────────
    log_level: str = "INFO"
    log_dir: str = "./logs"
    log_max_bytes: int = 10_485_760   # 10 MB
    log_backup_count: int = 5

    # ── CORS ─────────────────────────────────────────────────────
    cors_origins: list[str] = ["*"]  # Tighten in production

    @field_validator("debug", mode="before")
    @classmethod
    def parse_debug(cls, value):
        """Accept common non-boolean deployment flags like 'release'."""
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"release", "prod", "production", "off", "false", "0", "no"}:
                return False
            if normalized in {"debug", "dev", "development", "on", "true", "1", "yes"}:
                return True
        return value


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings singleton — import and call this everywhere."""
    return Settings()
