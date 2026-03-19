"""
GeoIP and ASN lookup using MaxMind GeoLite2 local databases.
Gracefully returns empty dict for private IPs or if DB files are missing.
"""
from __future__ import annotations

import ipaddress
from typing import Optional

from app.config import get_settings
from app.core.logger import get_logger

log = get_logger("geo_lookup")
settings = get_settings()

_city_reader = None
_asn_reader = None


def _get_readers():
    global _city_reader, _asn_reader
    if _city_reader is None:
        try:
            import geoip2.database  # type: ignore
            _city_reader = geoip2.database.Reader(settings.geoip_db_path)
            _asn_reader = geoip2.database.Reader(settings.geoip_asn_db_path)
        except Exception as exc:
            log.warning("geo_lookup.db_unavailable", error=str(exc))
    return _city_reader, _asn_reader


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def lookup(ip: str) -> dict:
    """
    Return GeoIP + ASN info for an IP.
    Returns empty dict for private IPs or if lookup fails.
    """
    if not ip or _is_private(ip):
        return {}

    city_reader, asn_reader = _get_readers()
    result: dict = {}

    if city_reader:
        try:
            city = city_reader.city(ip)
            result["country"] = city.country.name
            result["city"] = city.city.name
            result["latitude"] = city.location.latitude
            result["longitude"] = city.location.longitude
        except Exception:
            pass

    if asn_reader:
        try:
            asn = asn_reader.asn(ip)
            result["asn"] = f"AS{asn.autonomous_system_number}"
            result["org"] = asn.autonomous_system_organization
        except Exception:
            pass

    return result
