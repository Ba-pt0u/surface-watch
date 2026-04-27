"""
dns.py — DNS Collector.

Enumerates DNS records for root domains (A, AAAA, CNAME, MX, NS, TXT, SOA),
attempts zone transfers (AXFR), and optionally brute-forces subdomains
from a wordlist.
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import dns.exception
import dns.name
import dns.query
import dns.resolver
import dns.zone
import tldextract

from surface_watch import config
from surface_watch.collectors.base import BaseCollector
from surface_watch.models import (
    Asset, CollectorResult, DNSRecord, Domain, Edge, EdgeType, IPAddress, Subdomain,
)

log = logging.getLogger(__name__)

_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]


class DNSCollector(BaseCollector):
    name = "dns"

    def __init__(self) -> None:
        self._settings = config.SETTINGS.get("dns", {})
        self._bruteforce = self._settings.get("bruteforce_enabled", True)
        self._concurrency = self._settings.get("concurrency", 50)
        self._timeout = self._settings.get("timeout", 5)
        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = self._timeout
        self._resolver.lifetime = self._timeout * 2
        self._wordlist = self._load_wordlist()

    def _load_wordlist(self) -> list[str]:
        wl_path = self._settings.get("wordlist", "wordlist.txt")
        path = config.CONFIG_DIR / wl_path
        if not path.exists():
            log.warning("Wordlist not found: %s", path)
            return []
        words = [w.strip() for w in path.read_text(encoding="utf-8").splitlines() if w.strip() and not w.startswith("#")]
        log.info("Loaded %d words from wordlist", len(words))
        return words

    def collect(self) -> CollectorResult:
        assets: list[Asset] = []
        edges: list[Edge] = []
        errors: list[str] = []

        root_domains: list[str] = config.ALL_DOMAINS
        exclusions = set(config.SCOPE.get("exclusions", {}).get("domains", []))

        for domain in root_domains:
            if domain in exclusions:
                continue

            # Resolve organization for this domain
            org_id = config.DOMAIN_TO_ORG.get(domain, {}).get("id", "")

            # Create domain node
            dom_asset = Domain(uid=domain, fqdn=domain, source=self.name, organization=org_id)
            assets.append(dom_asset)

            # Resolve standard record types
            self._resolve_domain(domain, domain, org_id, assets, edges, errors)

            # Attempt zone transfer
            self._try_axfr(domain, org_id, assets, edges, errors)

            # Brute-force subdomains
            if self._bruteforce and self._wordlist:
                self._bruteforce_subdomains(domain, org_id, assets, edges, errors, exclusions)

        return CollectorResult(collector_name=self.name, assets=assets, edges=edges, errors=errors)

    def _resolve_domain(
        self, fqdn: str, root_domain: str, org_id: str,
        assets: list[Asset], edges: list[Edge], errors: list[str],
    ) -> None:
        """Resolve all record types for a given FQDN."""
        for rrtype in _RECORD_TYPES:
            try:
                answers = self._resolver.resolve(fqdn, rrtype)
                for rdata in answers:
                    rdata_str = rdata.to_text().rstrip(".")

                    # DNS record node
                    rec_uid = f"{fqdn}:{rrtype}:{rdata_str}"
                    assets.append(DNSRecord(
                        uid=rec_uid, fqdn=fqdn, rrtype=rrtype,
                        rdata=rdata_str, ttl=answers.rrset.ttl,
                        source=self.name, organization=org_id,
                    ))
                    edges.append(Edge(source_uid=fqdn, target_uid=rec_uid, edge_type=EdgeType.HAS_DNS_RECORD))

                    # If A/AAAA, create IP node + edge
                    if rrtype in ("A", "AAAA"):
                        ip_asset = IPAddress(
                            uid=rdata_str, address=rdata_str,
                            version=4 if rrtype == "A" else 6,
                            source=self.name, organization=org_id,
                        )
                        assets.append(ip_asset)
                        edges.append(Edge(source_uid=fqdn, target_uid=rdata_str, edge_type=EdgeType.RESOLVES_TO))

                    # If CNAME, create subdomain/target node + edges
                    if rrtype == "CNAME":
                        sub = Subdomain(uid=rdata_str, fqdn=rdata_str, parent_domain=root_domain,
                                        source=self.name, organization=org_id)
                        assets.append(sub)
                        # Direct resolution edge: source --resolves_to--> cname_target
                        edges.append(Edge(source_uid=fqdn, target_uid=rdata_str, edge_type=EdgeType.RESOLVES_TO))
                        # Parent domain owns this subdomain (if target is under the same root)
                        if rdata_str.endswith(f".{root_domain}") or rdata_str == root_domain:
                            edges.append(Edge(source_uid=root_domain, target_uid=rdata_str, edge_type=EdgeType.HAS_SUBDOMAIN))

            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                pass
            except dns.exception.DNSException as exc:
                errors.append(f"DNS {rrtype} {fqdn}: {exc}")

    def _try_axfr(
        self, domain: str, org_id: str,
        assets: list[Asset], edges: list[Edge], errors: list[str],
    ) -> None:
        """Attempt a zone transfer (AXFR) — usually blocked but worth trying."""
        try:
            ns_answers = self._resolver.resolve(domain, "NS")
        except dns.exception.DNSException:
            return

        for ns_rdata in ns_answers:
            ns_host = ns_rdata.to_text().rstrip(".")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=self._timeout))
                log.warning("[dns] AXFR succeeded for %s via %s — zone transfer allowed!", domain, ns_host)
                for name, node in zone.nodes.items():
                    fqdn = f"{name}.{domain}".rstrip(".")
                    if fqdn != domain:
                        sub = Subdomain(uid=fqdn, fqdn=fqdn, parent_domain=domain,
                                        source=f"{self.name}:axfr", organization=org_id)
                        assets.append(sub)
                        edges.append(Edge(source_uid=domain, target_uid=fqdn, edge_type=EdgeType.HAS_SUBDOMAIN))
                break  # one successful AXFR is enough
            except Exception:
                pass  # AXFR refused — expected

    def _bruteforce_subdomains(
        self, domain: str, org_id: str,
        assets: list[Asset], edges: list[Edge], errors: list[str],
        exclusions: set[str],
    ) -> None:
        """Brute-force subdomain discovery from wordlist."""
        candidates = [f"{word}.{domain}" for word in self._wordlist]

        def _check(fqdn: str) -> str | None:
            if fqdn in exclusions:
                return None
            try:
                self._resolver.resolve(fqdn, "A")
                return fqdn
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                return None
            except dns.exception.DNSException:
                return None

        found = 0
        with ThreadPoolExecutor(max_workers=self._concurrency) as pool:
            futures = {pool.submit(_check, c): c for c in candidates}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found += 1
                    sub = Subdomain(uid=result, fqdn=result, parent_domain=domain,
                                    source=f"{self.name}:brute", organization=org_id)
                    assets.append(sub)
                    edges.append(Edge(source_uid=domain, target_uid=result, edge_type=EdgeType.HAS_SUBDOMAIN))
                    # Also resolve its records
                    self._resolve_domain(result, domain, org_id, assets, edges, errors)

        log.info("[dns] Brute-force on %s: %d/%d subdomains found", domain, found, len(candidates))
