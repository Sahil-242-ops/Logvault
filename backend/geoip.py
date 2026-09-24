"""
Offline IP geolocation. Reads a MaxMind-format .mmdb (DB-IP City Lite or GeoLite2-City)
from config.GEOIP_DIR. No network access is ever made.
"""
import glob
import ipaddress
import os
from functools import lru_cache
from typing import Any, Dict, Optional

from .config import config

try:
    import maxminddb
except ImportError:  # dependency missing -> internal/unknown classification only
    maxminddb = None


class GeoIP:
    def __init__(self):
        self._reader = None
        self.db_name: Optional[str] = None
        self._load()

    def _load(self):
        if maxminddb is None:
            return
        files = sorted(glob.glob(os.path.join(config.GEOIP_DIR, "*.mmdb")))
        if not files:
            return
        try:
            self._reader = maxminddb.open_database(files[0])
            self.db_name = os.path.basename(files[0])
        except Exception as e:
            print(f"[GEOIP] Failed to open {files[0]}: {e}")

    @property
    def available(self) -> bool:
        return self._reader is not None

    @lru_cache(maxsize=65536)
    def lookup(self, ip: Optional[str]) -> Dict[str, Any]:
        if not ip:
            return {"scope": "unknown"}
        try:
            addr = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            return {"scope": "unknown"}

        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast:
            # RFC1918 / loopback / documentation ranges never leave the site
            return {"scope": "internal"}

        if not self._reader:
            return {"scope": "external", "resolved": False}

        try:
            rec = self._reader.get(str(addr)) or {}
        except Exception:
            rec = {}
        loc = rec.get("location") or {}
        if "latitude" not in loc:
            return {"scope": "external", "resolved": False}

        country = rec.get("country") or {}
        city = rec.get("city") or {}
        return {
            "scope": "external",
            "resolved": True,
            "country": (country.get("names") or {}).get("en"),
            "country_code": country.get("iso_code"),
            "city": (city.get("names") or {}).get("en"),
            "lat": loc["latitude"],
            "lon": loc["longitude"],
        }


geoip = GeoIP()
