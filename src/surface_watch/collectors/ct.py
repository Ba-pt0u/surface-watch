"""
ct.py — Certificate Transparency Collector.

Two modes:
  - Batch: queries crt.sh API for all certificates matching root domains
  - Realtime: connects to certstream WebSocket for live monitoring

Includes typosquatting detection via Levenshtein distance.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any

import httpx
import tldextract

from surface_watch import config
from surface_watch.collectors.base import BaseCollector
from surface_watch.models import (
    Asset, Certificate, CollectorResult, Edge, EdgeType, Subdomain,
)

log = logging.getLogger(__name__)


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        cur_row = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            cur_row.append(min(cur_row[j] + 1, prev_row[j + 1] + 1, prev_row[j] + cost))
        prev_row = cur_row
    return prev_row[-1]


class CTBatchCollector(BaseCollector):
    """Query crt.sh for certificates matching scope domains."""

    name = "ct_batch"

    def __init__(self) -> None:
        self._ct_settings = config.SETTINGS.get("ct", {})
        self._rate_limit = self._ct_settings.get("crtsh_rate_limit", 1.0)
        self._typosquat_dist = self._ct_settings.get("typosquat_max_distance", 2)

    def collect(self) -> CollectorResult:
        assets: list[Asset] = []
        edges: list[Edge] = []
        errors: list[str] = []

        root_domains: list[str] = config.SCOPE.get("domains", [])

        for domain in root_domains:
            try:
                certs = self._query_crtsh(domain)
                self._process_certs(domain, certs, assets, edges)
                log.info("[ct_batch] %s: %d certificates found", domain, len(certs))
            except Exception as exc:
                errors.append(f"crt.sh query for {domain}: {exc}")
                log.error("[ct_batch] Error querying crt.sh for %s: %s", domain, exc)

            # Respect rate limit between domain queries
            time.sleep(1.0 / self._rate_limit)

        return CollectorResult(collector_name=self.name, assets=assets, edges=edges, errors=errors)

    def _query_crtsh(self, domain: str) -> list[dict[str, Any]]:
        """Query crt.sh API for certificates matching %.domain."""
        url = "https://crt.sh/"
        params = {"q": f"%.{domain}", "output": "json"}

        # verify=False handles corporate TLS inspection proxies.
        # crt.sh is a public read-only service — no credentials exposed.
        with httpx.Client(timeout=30, follow_redirects=True, verify=False) as client:
            resp = client.get(url, params=params)
            resp.raise_for_status()
            return resp.json()

    def _process_certs(
        self, root_domain: str, certs: list[dict[str, Any]],
        assets: list[Asset], edges: list[Edge],
    ) -> None:
        """Process crt.sh results into Certificate + Subdomain assets."""
        seen_certs: set[str] = set()
        seen_names: set[str] = set()

        for entry in certs:
            # Deduplicate by certificate ID
            cert_id = str(entry.get("id", ""))
            if cert_id in seen_certs:
                continue
            seen_certs.add(cert_id)

            serial = entry.get("serial_number", "")
            issuer = entry.get("issuer_name", "")
            not_before = entry.get("not_before", "")
            not_after = entry.get("not_after", "")
            common_name = entry.get("common_name", "")
            name_value = entry.get("name_value", "")

            # Parse SANs from name_value (newline-separated)
            sans = set()
            if name_value:
                for name in name_value.replace("\n", " ").split():
                    name = name.strip().lower().lstrip("*.")
                    if name and "." in name:
                        sans.add(name)
            if common_name:
                cn = common_name.strip().lower().lstrip("*.")
                if cn and "." in cn:
                    sans.add(cn)

            if not sans:
                continue

            # Certificate node
            cert_uid = f"cert:{serial or cert_id}"
            cert_asset = Certificate(
                uid=cert_uid, sha256="", serial=serial,
                issuer=issuer, not_before=not_before, not_after=not_after,
                sans=sorted(sans), source=self.name,
            )
            assets.append(cert_asset)

            # Subdomain nodes from SANs
            for san in sans:
                if san in seen_names:
                    continue
                seen_names.add(san)

                # Check if this SAN belongs to our root domain
                ext = tldextract.extract(san)
                registered = f"{ext.domain}.{ext.suffix}"

                if registered == root_domain or san.endswith(f".{root_domain}"):
                    if san != root_domain:
                        sub = Subdomain(
                            uid=san, fqdn=san, parent_domain=root_domain,
                            source=self.name,
                        )
                        assets.append(sub)
                        edges.append(Edge(
                            source_uid=root_domain, target_uid=san,
                            edge_type=EdgeType.HAS_SUBDOMAIN,
                        ))

                # Certificate -> SAN edge
                edges.append(Edge(
                    source_uid=cert_uid, target_uid=san,
                    edge_type=EdgeType.ISSUED_FOR,
                ))


class CTStreamListener:
    """
    Real-time Certificate Transparency monitor using certstream.

    Runs in a background thread and calls a callback when a relevant
    certificate is seen.
    """

    def __init__(self, callback: Any = None) -> None:
        self._domains = set(config.SCOPE.get("domains", []))
        self._ct_settings = config.SETTINGS.get("ct", {})
        self._typosquat_dist = self._ct_settings.get("typosquat_max_distance", 2)
        self._callback = callback
        self._thread: threading.Thread | None = None
        self._running = False

    def start(self) -> None:
        """Start the certstream listener in a background thread."""
        if not self._domains:
            log.warning("[ct_stream] No domains configured, skipping certstream")
            return
        self._running = True
        self._thread = threading.Thread(target=self._listen, daemon=True, name="certstream")
        self._thread.start()
        log.info("[ct_stream] Certstream listener started for %d domains", len(self._domains))

    def stop(self) -> None:
        self._running = False

    def _listen(self) -> None:
        """Connect to certstream and process events."""
        try:
            import certstream
        except ImportError:
            log.error("[ct_stream] certstream package not installed")
            return

        while self._running:
            try:
                certstream.listen_for_events(
                    self._on_message,
                    url="wss://certstream.calidog.io/",
                )
            except Exception as exc:
                log.warning("[ct_stream] Connection lost (%s), reconnecting in 10s...", exc)
                time.sleep(10)

    def _on_message(self, message: dict, context: Any) -> None:
        """Process a certstream message."""
        if message.get("message_type") != "certificate_update":
            return

        data = message.get("data", {})
        leaf = data.get("leaf_cert", {})
        all_domains = leaf.get("all_domains", [])

        if not all_domains:
            return

        for cert_domain in all_domains:
            cert_domain = cert_domain.lower().lstrip("*.")
            if not cert_domain or "." not in cert_domain:
                continue

            # Check exact match against scope domains
            for scope_domain in self._domains:
                if cert_domain == scope_domain or cert_domain.endswith(f".{scope_domain}"):
                    self._alert_new_cert(cert_domain, scope_domain, leaf, typosquat=False)
                    break
                # Check typosquatting (Levenshtein distance on the registered domain part)
                ext = tldextract.extract(cert_domain)
                cert_registered = ext.domain
                scope_ext = tldextract.extract(scope_domain)
                scope_registered = scope_ext.domain
                if cert_registered != scope_registered:
                    dist = _levenshtein(cert_registered, scope_registered)
                    if 0 < dist <= self._typosquat_dist and ext.suffix == scope_ext.suffix:
                        self._alert_new_cert(cert_domain, scope_domain, leaf, typosquat=True)
                        break

    def _alert_new_cert(self, cert_domain: str, scope_domain: str, leaf: dict, typosquat: bool) -> None:
        """Generate an alert for a new certificate."""
        alert_type = "typosquat_cert" if typosquat else "new_certificate"
        log.warning(
            "[ct_stream] %s: %s (scope: %s) — issuer: %s",
            alert_type.upper(), cert_domain, scope_domain,
            leaf.get("issuer", {}).get("O", "unknown"),
        )
        if self._callback:
            self._callback(alert_type, cert_domain, scope_domain, leaf)
