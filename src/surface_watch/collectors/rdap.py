"""
rdap.py — RDAP / WHOIS Collector.

Enriches domains with registrant info, registrar, creation/expiry dates.
Enriches IP addresses with ASN and organization data.
"""
from __future__ import annotations

import logging
import time
from typing import Any

from surface_watch import config
from surface_watch.collectors.base import BaseCollector
from surface_watch.models import (
    Asset, CollectorResult, Domain, Edge, IPAddress,
)

log = logging.getLogger(__name__)

_RATE_LIMIT_DELAY = 0.5  # seconds between RDAP queries


class RDAPCollector(BaseCollector):
    """Enrich domains with WHOIS/RDAP data and IPs with ASN info."""

    name = "rdap"

    def collect(self) -> CollectorResult:
        assets: list[Asset] = []
        edges: list[Edge] = []
        errors: list[str] = []

        root_domains: list[str] = config.SCOPE.get("domains", [])

        # Enrich root domains with WHOIS data
        for domain in root_domains:
            try:
                info = self._whois_domain(domain)
                if info:
                    dom = Domain(
                        uid=domain, fqdn=domain, source=self.name,
                        registrar=info.get("registrar", ""),
                        whois_org=info.get("org", ""),
                        created=info.get("created", ""),
                        expires=info.get("expires", ""),
                        nameservers=info.get("nameservers", []),
                    )
                    assets.append(dom)
                time.sleep(_RATE_LIMIT_DELAY)
            except Exception as exc:
                errors.append(f"WHOIS {domain}: {exc}")
                log.warning("[rdap] WHOIS error for %s: %s", domain, exc)

        return CollectorResult(collector_name=self.name, assets=assets, edges=edges, errors=errors)

    def _whois_domain(self, domain: str) -> dict[str, Any] | None:
        """Query RDAP/WHOIS for domain registration info."""
        try:
            import httpx

            # Try RDAP first (modern, structured)
            rdap_url = f"https://rdap.org/domain/{domain}"
            with httpx.Client(timeout=15, follow_redirects=True) as client:
                resp = client.get(rdap_url)
                if resp.status_code == 200:
                    data = resp.json()
                    return self._parse_rdap_domain(data)
        except Exception as exc:
            log.debug("[rdap] RDAP failed for %s: %s, trying python-whois", domain, exc)

        # Fallback: try socket-based whois via subprocess
        try:
            import subprocess
            result = subprocess.run(
                ["whois", domain],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0:
                return self._parse_whois_text(result.stdout)
        except FileNotFoundError:
            log.debug("[rdap] whois command not available")
        except Exception as exc:
            log.debug("[rdap] whois subprocess failed for %s: %s", domain, exc)

        return None

    def _parse_rdap_domain(self, data: dict) -> dict[str, Any]:
        """Parse RDAP response for domain info."""
        info: dict[str, Any] = {}

        # Registrar
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            if "registrar" in roles:
                vcard = entity.get("vcardArray", [None, []])[1] if entity.get("vcardArray") else []
                for item in (vcard or []):
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                        info["registrar"] = item[3]

        # Events (registration, expiration)
        for event in data.get("events", []):
            action = event.get("eventAction", "")
            date = event.get("eventDate", "")
            if action == "registration":
                info["created"] = date
            elif action == "expiration":
                info["expires"] = date

        # Nameservers
        ns_list = []
        for ns in data.get("nameservers", []):
            ns_name = ns.get("ldhName", "")
            if ns_name:
                ns_list.append(ns_name.lower())
        info["nameservers"] = ns_list

        return info

    def _parse_whois_text(self, text: str) -> dict[str, Any]:
        """Parse raw whois text output."""
        info: dict[str, Any] = {"nameservers": []}
        for line in text.splitlines():
            line = line.strip()
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if not value:
                continue

            if "registrar" in key and "registrar" not in info:
                info["registrar"] = value
            elif key in ("creation date", "created"):
                info["created"] = value
            elif key in ("registry expiry date", "expiry date", "expires"):
                info["expires"] = value
            elif key in ("registrant organization", "org-name"):
                info["org"] = value
            elif key == "name server":
                info["nameservers"].append(value.lower())

        return info


class IPEnrichCollector(BaseCollector):
    """Enrich discovered IP addresses with ASN and geolocation data."""

    name = "ipinfo"

    def collect(self) -> CollectorResult:
        assets: list[Asset] = []
        edges: list[Edge] = []
        errors: list[str] = []

        # This collector needs the graph to know which IPs exist.
        # It will be called with IPs passed explicitly via set_ips().
        for ip_addr in self._ips:
            try:
                info = self._lookup_ip(ip_addr)
                if info:
                    ip = IPAddress(
                        uid=ip_addr, address=ip_addr,
                        version=4 if "." in ip_addr else 6,
                        asn=info.get("asn"),
                        asn_org=info.get("asn_org", ""),
                        country=info.get("country", ""),
                        source=self.name,
                    )
                    assets.append(ip)
                time.sleep(0.2)  # rate limit
            except Exception as exc:
                errors.append(f"IP info {ip_addr}: {exc}")

        return CollectorResult(collector_name=self.name, assets=assets, edges=edges, errors=errors)

    def __init__(self) -> None:
        self._ips: set[str] = set()

    def set_ips(self, ips: set[str]) -> None:
        """Set the IPs to enrich (called by orchestrator after other collectors run)."""
        self._ips = ips

    def _lookup_ip(self, ip_addr: str) -> dict[str, Any] | None:
        """Query ipinfo.io API for ASN / org / country info.

        Free tier: 50 000 req/month without token.
        Set IPINFO_TOKEN in .env for higher limits.
        """
        try:
            import httpx
            url = f"https://ipinfo.io/{ip_addr}/json"
            headers = {}
            if config.IPINFO_TOKEN:
                headers["Authorization"] = f"Bearer {config.IPINFO_TOKEN}"
            with httpx.Client(timeout=10, headers=headers) as client:
                resp = client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    # org field is "AS1234 Example Corp"
                    org_raw = data.get("org", "")
                    asn, _, asn_org = org_raw.partition(" ")
                    return {
                        "asn": asn.lstrip("AS") or None,
                        "asn_org": asn_org,
                        "country": data.get("country", ""),
                    }
        except Exception as exc:
            log.debug("[ipinfo] Lookup failed for %s: %s", ip_addr, exc)
        return None
