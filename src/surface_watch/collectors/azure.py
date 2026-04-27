"""
azure.py — Azure / Entra ID Collector.

Discovers cloud-exposed assets:
  - Public IP addresses
  - Azure DNS zones and records
  - App Service hostnames
  - Entra ID app registrations (redirect URIs, identifier URIs)
  - Entra ID verified domains

Requires AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET in .env.
"""
from __future__ import annotations

import logging
from typing import Any

from surface_watch import config
from surface_watch.collectors.base import BaseCollector
from surface_watch.models import (
    Asset, CloudResource, CollectorResult, Domain, Edge, EdgeType, IPAddress, Subdomain,
)

log = logging.getLogger(__name__)


class AzureCollector(BaseCollector):
    name = "azure"

    def collect(self) -> CollectorResult:
        if not config.AZURE_ENABLED:
            log.info("[azure] Azure credentials not configured, skipping")
            return CollectorResult(collector_name=self.name)

        assets: list[Asset] = []
        edges: list[Edge] = []
        errors: list[str] = []

        try:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.resource import ResourceManagementClient, SubscriptionClient
            from azure.mgmt.network import NetworkManagementClient
            from azure.mgmt.dns import DnsManagementClient
            from azure.mgmt.web import WebSiteManagementClient
        except ImportError as exc:
            errors.append(f"Azure SDK not installed: {exc}")
            return CollectorResult(collector_name=self.name, errors=errors)

        try:
            credential = ClientSecretCredential(
                tenant_id=config.AZURE_TENANT_ID,
                client_id=config.AZURE_CLIENT_ID,
                client_secret=config.AZURE_CLIENT_SECRET,
            )

            # Get all subscriptions
            sub_client = SubscriptionClient(credential)
            subscriptions = list(sub_client.subscriptions.list())
            log.info("[azure] Found %d subscriptions", len(subscriptions))

            for sub in subscriptions:
                sub_id = sub.subscription_id
                sub_name = sub.display_name or sub_id

                # Public IPs
                self._collect_public_ips(credential, sub_id, sub_name, assets, edges, errors)

                # DNS Zones
                self._collect_dns_zones(credential, sub_id, sub_name, assets, edges, errors)

                # App Services
                self._collect_app_services(credential, sub_id, sub_name, assets, edges, errors)

            # Entra ID (tenant-level)
            self._collect_entra_id(credential, assets, edges, errors)

        except Exception as exc:
            errors.append(f"Azure collection error: {exc}")
            log.exception("[azure] Collection failed")

        return CollectorResult(collector_name=self.name, assets=assets, edges=edges, errors=errors)

    def _collect_public_ips(
        self, credential: Any, sub_id: str, sub_name: str,
        assets: list[Asset], edges: list[Edge], errors: list[str],
    ) -> None:
        """Collect all public IP addresses from a subscription."""
        try:
            from azure.mgmt.network import NetworkManagementClient
            net_client = NetworkManagementClient(credential, sub_id)

            for pip in net_client.public_ip_addresses.list_all():
                ip_addr = pip.ip_address
                if not ip_addr:
                    continue

                # Cloud resource node
                res_uid = f"azure:{pip.id}"
                res = CloudResource(
                    uid=res_uid, provider="azure", resource_type="PublicIPAddress",
                    resource_id=pip.id or "", name=pip.name or "",
                    subscription=sub_name, resource_group=self._extract_rg(pip.id or ""),
                    source=self.name,
                )
                assets.append(res)

                # IP node
                ip = IPAddress(uid=ip_addr, address=ip_addr, version=4, source=self.name)
                assets.append(ip)
                edges.append(Edge(source_uid=res_uid, target_uid=ip_addr, edge_type=EdgeType.HAS_PUBLIC_IP))

                # DNS name if set
                if pip.dns_settings and pip.dns_settings.fqdn:
                    fqdn = pip.dns_settings.fqdn.rstrip(".")
                    sub_asset = Subdomain(uid=fqdn, fqdn=fqdn, parent_domain="", source=self.name)
                    assets.append(sub_asset)
                    edges.append(Edge(source_uid=res_uid, target_uid=fqdn, edge_type=EdgeType.HAS_HOSTNAME))
                    edges.append(Edge(source_uid=fqdn, target_uid=ip_addr, edge_type=EdgeType.RESOLVES_TO))

        except Exception as exc:
            errors.append(f"Public IPs ({sub_name}): {exc}")

    def _collect_dns_zones(
        self, credential: Any, sub_id: str, sub_name: str,
        assets: list[Asset], edges: list[Edge], errors: list[str],
    ) -> None:
        """Collect Azure DNS zones and their record sets."""
        try:
            from azure.mgmt.dns import DnsManagementClient
            dns_client = DnsManagementClient(credential, sub_id)

            for zone in dns_client.zones.list():
                zone_name = zone.name or ""
                res_uid = f"azure:{zone.id}"
                res = CloudResource(
                    uid=res_uid, provider="azure", resource_type="DnsZone",
                    resource_id=zone.id or "", name=zone_name,
                    subscription=sub_name, resource_group=self._extract_rg(zone.id or ""),
                    source=self.name,
                )
                assets.append(res)

                # Domain node for the zone
                dom = Domain(uid=zone_name, fqdn=zone_name, source=self.name)
                assets.append(dom)
                edges.append(Edge(source_uid=res_uid, target_uid=zone_name, edge_type=EdgeType.HAS_HOSTNAME))

                # Record sets
                rg = self._extract_rg(zone.id or "")
                if rg:
                    try:
                        for rs in dns_client.record_sets.list_by_dns_zone(rg, zone_name):
                            self._process_dns_recordset(zone_name, rs, assets, edges)
                    except Exception as exc:
                        errors.append(f"DNS records ({zone_name}): {exc}")

        except Exception as exc:
            errors.append(f"DNS zones ({sub_name}): {exc}")

    def _process_dns_recordset(
        self, zone_name: str, rs: Any,
        assets: list[Asset], edges: list[Edge],
    ) -> None:
        """Process a single Azure DNS record set."""
        rs_name = rs.name or ""
        fqdn = f"{rs_name}.{zone_name}".rstrip(".") if rs_name != "@" else zone_name

        # A records
        if rs.a_records:
            for rec in rs.a_records:
                ip_addr = rec.ipv4_address
                ip = IPAddress(uid=ip_addr, address=ip_addr, version=4, source=self.name)
                assets.append(ip)
                if fqdn != zone_name:
                    sub = Subdomain(uid=fqdn, fqdn=fqdn, parent_domain=zone_name, source=self.name)
                    assets.append(sub)
                    edges.append(Edge(source_uid=zone_name, target_uid=fqdn, edge_type=EdgeType.HAS_SUBDOMAIN))
                edges.append(Edge(source_uid=fqdn, target_uid=ip_addr, edge_type=EdgeType.RESOLVES_TO))

        # AAAA records
        if rs.aaaa_records:
            for rec in rs.aaaa_records:
                ip_addr = rec.ipv6_address
                ip = IPAddress(uid=ip_addr, address=ip_addr, version=6, source=self.name)
                assets.append(ip)
                edges.append(Edge(source_uid=fqdn, target_uid=ip_addr, edge_type=EdgeType.RESOLVES_TO))

        # CNAME records
        if rs.cname_record and rs.cname_record.cname:
            target = rs.cname_record.cname.rstrip(".")
            sub = Subdomain(uid=fqdn, fqdn=fqdn, parent_domain=zone_name, source=self.name)
            assets.append(sub)
            edges.append(Edge(source_uid=zone_name, target_uid=fqdn, edge_type=EdgeType.HAS_SUBDOMAIN))

    def _collect_app_services(
        self, credential: Any, sub_id: str, sub_name: str,
        assets: list[Asset], edges: list[Edge], errors: list[str],
    ) -> None:
        """Collect App Service hostnames."""
        try:
            from azure.mgmt.web import WebSiteManagementClient
            web_client = WebSiteManagementClient(credential, sub_id)

            for site in web_client.web_apps.list():
                res_uid = f"azure:{site.id}"
                res = CloudResource(
                    uid=res_uid, provider="azure", resource_type="AppService",
                    resource_id=site.id or "", name=site.name or "",
                    subscription=sub_name, resource_group=self._extract_rg(site.id or ""),
                    source=self.name,
                )
                assets.append(res)

                # Hostnames
                for hostname in (site.host_names or []):
                    hostname = hostname.rstrip(".")
                    sub = Subdomain(uid=hostname, fqdn=hostname, parent_domain="", source=self.name)
                    assets.append(sub)
                    edges.append(Edge(source_uid=res_uid, target_uid=hostname, edge_type=EdgeType.HAS_HOSTNAME))

        except Exception as exc:
            errors.append(f"App Services ({sub_name}): {exc}")

    def _collect_entra_id(
        self, credential: Any,
        assets: list[Asset], edges: list[Edge], errors: list[str],
    ) -> None:
        """Collect Entra ID app registrations and verified domains."""
        try:
            import msal
            import requests

            app = msal.ConfidentialClientApplication(
                config.AZURE_CLIENT_ID,
                authority=f"https://login.microsoftonline.com/{config.AZURE_TENANT_ID}",
                client_credential=config.AZURE_CLIENT_SECRET,
            )
            result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
            if "access_token" not in result:
                errors.append(f"Entra ID auth failed: {result.get('error_description', 'unknown')}")
                return

            token = result["access_token"]
            headers = {"Authorization": f"Bearer {token}"}
            session = requests.Session()
            session.headers.update(headers)

            # Verified domains
            resp = session.get("https://graph.microsoft.com/v1.0/domains", timeout=30)
            if resp.ok:
                for dom_data in resp.json().get("value", []):
                    dom_id = dom_data.get("id", "")
                    if dom_id:
                        dom = Domain(
                            uid=dom_id, fqdn=dom_id, source=f"{self.name}:entra",
                            attrs={"verified": dom_data.get("isVerified", False)},
                        )
                        assets.append(dom)

            # App registrations — check redirect URIs for exposed URLs
            url: str | None = "https://graph.microsoft.com/v1.0/applications?$select=displayName,appId,web,spa,identifierUris"
            while url:
                resp = session.get(url, timeout=30)
                if not resp.ok:
                    break
                data = resp.json()
                for app_data in data.get("value", []):
                    self._process_app_registration(app_data, assets, edges)
                url = data.get("@odata.nextLink")

        except Exception as exc:
            errors.append(f"Entra ID: {exc}")

    def _process_app_registration(
        self, app_data: dict, assets: list[Asset], edges: list[Edge],
    ) -> None:
        """Extract URLs from an Entra ID app registration."""
        app_name = app_data.get("displayName", "")
        app_id = app_data.get("appId", "")
        res_uid = f"azure:app:{app_id}"

        res = CloudResource(
            uid=res_uid, provider="azure", resource_type="AppRegistration",
            resource_id=app_id, name=app_name, source=f"{self.name}:entra",
        )
        assets.append(res)

        # Collect all URLs from web redirect URIs, SPA redirect URIs, identifier URIs
        urls: list[str] = []
        web = app_data.get("web", {}) or {}
        urls.extend(web.get("redirectUris", []))
        spa = app_data.get("spa", {}) or {}
        urls.extend(spa.get("redirectUris", []))
        urls.extend(app_data.get("identifierUris", []))

        for url in urls:
            # Extract hostname from URL
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                hostname = parsed.hostname
                if hostname and hostname not in ("localhost", "127.0.0.1", "::1"):
                    sub = Subdomain(uid=hostname, fqdn=hostname, parent_domain="", source=f"{self.name}:entra")
                    assets.append(sub)
                    edges.append(Edge(source_uid=res_uid, target_uid=hostname, edge_type=EdgeType.HAS_HOSTNAME))
            except Exception:
                pass

    @staticmethod
    def _extract_rg(resource_id: str) -> str:
        """Extract resource group name from an Azure resource ID."""
        parts = resource_id.split("/")
        for i, part in enumerate(parts):
            if part.lower() == "resourcegroups" and i + 1 < len(parts):
                return parts[i + 1]
        return ""
