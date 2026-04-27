"""
portscan.py — Lightweight port scanner collector.

Uses python-nmap to scan discovered IPs + manual IP ranges.
Top 100 TCP ports with service detection.
Also grabs TLS certificates on ports 443/8443.
"""
from __future__ import annotations

import logging
import socket
import ssl
from ipaddress import IPv4Network, IPv6Network, ip_address
from typing import Any

from surface_watch import config
from surface_watch.collectors.base import BaseCollector
from surface_watch.models import (
    Asset, Certificate, CollectorResult, Edge, EdgeType, IPAddress, PortService,
)

log = logging.getLogger(__name__)


class PortScanCollector(BaseCollector):
    """Scan IPs for open ports and grab TLS certificates."""

    name = "portscan"

    def __init__(self) -> None:
        self._settings = config.SETTINGS.get("portscan", {})
        self._top_ports = self._settings.get("top_ports", 100)
        self._nmap_args = self._settings.get("arguments", "-sV -Pn --open")
        self._timeout = self._settings.get("timeout", 300)
        self._tls_ports = self._settings.get("tls_grab_ports", [443, 8443])
        self._ips: set[str] = set()

    def set_ips(self, ips: set[str]) -> None:
        """Set target IPs (called by orchestrator after discovery collectors)."""
        self._ips = ips

    def collect(self) -> CollectorResult:
        assets: list[Asset] = []
        edges: list[Edge] = []
        errors: list[str] = []

        # Combine discovered IPs with manual IP ranges
        targets = set(self._ips)
        for cidr in config.SCOPE.get("ip_ranges", []):
            try:
                net = IPv4Network(cidr, strict=False) if "." in cidr else IPv6Network(cidr, strict=False)
                # Limit expansion to /24 max to avoid scanning huge ranges
                if net.num_addresses > 256:
                    log.warning("[portscan] Range %s has %d hosts, limiting to first 256", cidr, net.num_addresses)
                for i, host in enumerate(net.hosts()):
                    if i >= 256:
                        break
                    targets.add(str(host))
            except ValueError as exc:
                errors.append(f"Invalid CIDR {cidr}: {exc}")

        # Filter out excluded IPs
        excluded_ranges = config.SCOPE.get("exclusions", {}).get("ip_ranges", [])
        excluded_nets = []
        for cidr in excluded_ranges:
            try:
                excluded_nets.append(IPv4Network(cidr, strict=False) if "." in cidr else IPv6Network(cidr, strict=False))
            except ValueError:
                pass

        filtered_targets = set()
        for ip_str in targets:
            try:
                addr = ip_address(ip_str)
                if not any(addr in net for net in excluded_nets):
                    filtered_targets.add(ip_str)
            except ValueError:
                pass

        if not filtered_targets:
            log.info("[portscan] No targets to scan")
            return CollectorResult(collector_name=self.name, assets=assets, edges=edges, errors=errors)

        log.info("[portscan] Scanning %d targets (top %d ports)", len(filtered_targets), self._top_ports)

        # nmap scan
        try:
            import nmap
            scanner = nmap.PortScanner()
        except ImportError:
            errors.append("python-nmap not installed or nmap binary not found")
            return CollectorResult(collector_name=self.name, assets=assets, edges=edges, errors=errors)
        except Exception as exc:
            # nmap binary not found (e.g. Windows dev env — runs via Docker in prod)
            log.warning("[portscan] nmap not available: %s — skipping port scan", exc)
            errors.append(f"nmap not available: {exc}")
            return CollectorResult(collector_name=self.name, assets=assets, edges=edges, errors=errors)

        # Scan in batches to avoid command line length limits
        target_list = sorted(filtered_targets)
        batch_size = 50
        for i in range(0, len(target_list), batch_size):
            batch = target_list[i:i + batch_size]
            hosts_str = " ".join(batch)
            try:
                scanner.scan(
                    hosts=hosts_str,
                    arguments=f"--top-ports {self._top_ports} {self._nmap_args}",
                    timeout=self._timeout,
                )
                self._process_nmap_results(scanner, assets, edges, errors)
            except Exception as exc:
                errors.append(f"nmap scan batch {i}: {exc}")
                log.error("[portscan] nmap error: %s", exc)

        # TLS certificate grab on specific ports
        for ip_str in filtered_targets:
            for port in self._tls_ports:
                self._grab_tls_cert(ip_str, port, assets, edges, errors)

        return CollectorResult(collector_name=self.name, assets=assets, edges=edges, errors=errors)

    def _process_nmap_results(
        self, scanner: Any,
        assets: list[Asset], edges: list[Edge], errors: list[str],
    ) -> None:
        """Process nmap scan results into PortService assets."""
        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in ports:
                    port_info = scanner[host][proto][port]
                    state = port_info.get("state", "")
                    if state != "open":
                        continue

                    service = port_info.get("name", "")
                    product = port_info.get("product", "")
                    version = port_info.get("version", "")
                    extrainfo = port_info.get("extrainfo", "")

                    port_uid = f"{host}:{proto}/{port}"
                    ps = PortService(
                        uid=port_uid, ip=host, port=port,
                        protocol=proto, service=service,
                        product=product, version=version,
                        banner=extrainfo, source=self.name,
                    )
                    assets.append(ps)

                    # Ensure IP node exists
                    ip = IPAddress(uid=host, address=host, version=4 if "." in host else 6, source=self.name)
                    assets.append(ip)

                    edges.append(Edge(source_uid=host, target_uid=port_uid, edge_type=EdgeType.EXPOSES_PORT))

    def _grab_tls_cert(
        self, ip_addr: str, port: int,
        assets: list[Asset], edges: list[Edge], errors: list[str],
    ) -> None:
        """Attempt to grab TLS certificate from an IP:port."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # we want to grab even invalid certs

            with socket.create_connection((ip_addr, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip_addr) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    if not cert_bin:
                        return

                    from cryptography import x509
                    cert = x509.load_der_x509_certificate(cert_bin)

                    serial = format(cert.serial_number, "x")
                    issuer = cert.issuer.rfc4514_string()
                    not_before = cert.not_valid_before_utc.isoformat()
                    not_after = cert.not_valid_after_utc.isoformat()

                    # Extract SANs
                    sans: list[str] = []
                    try:
                        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                        sans = ext.value.get_values_for_type(x509.DNSName)
                    except x509.ExtensionNotFound:
                        pass
                    # Also add CN
                    for attr in cert.subject:
                        if attr.oid == x509.oid.NameOID.COMMON_NAME:
                            cn = attr.value
                            if cn and cn not in sans:
                                sans.append(cn)

                    # SHA-256 fingerprint
                    from cryptography.hazmat.primitives import hashes
                    sha256 = cert.fingerprint(hashes.SHA256()).hex()

                    cert_uid = f"cert:{sha256[:16]}"
                    cert_asset = Certificate(
                        uid=cert_uid, sha256=sha256, serial=serial,
                        issuer=issuer, not_before=not_before, not_after=not_after,
                        sans=sans, source=f"{self.name}:tls",
                    )
                    assets.append(cert_asset)
                    edges.append(Edge(source_uid=ip_addr, target_uid=cert_uid, edge_type=EdgeType.SERVES_CERT))

                    # Certificate -> SAN edges
                    for san in sans:
                        edges.append(Edge(source_uid=cert_uid, target_uid=san, edge_type=EdgeType.ISSUED_FOR))

        except (socket.timeout, ConnectionRefusedError, OSError):
            pass  # Port closed or filtered — expected
        except Exception as exc:
            log.debug("[portscan] TLS grab %s:%d failed: %s", ip_addr, port, exc)
