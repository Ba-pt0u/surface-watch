"""
models.py — Pydantic data models for assets, relationships, and collector results.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class AssetType(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    CERTIFICATE = "certificate"
    PORT_SERVICE = "port_service"
    CLOUD_RESOURCE = "cloud_resource"
    DNS_RECORD = "dns_record"


class EdgeType(str, Enum):
    HAS_SUBDOMAIN = "has_subdomain"
    RESOLVES_TO = "resolves_to"
    ISSUED_FOR = "issued_for"
    SERVES_CERT = "serves_cert"
    HAS_PUBLIC_IP = "has_public_ip"
    HAS_HOSTNAME = "has_hostname"
    BELONGS_TO_ASN = "belongs_to_asn"
    EXPOSES_PORT = "exposes_port"
    HAS_DNS_RECORD = "has_dns_record"


# ---------------------------------------------------------------------------
# Asset models
# ---------------------------------------------------------------------------

class Asset(BaseModel):
    """Base asset with a unique key and type."""
    uid: str                         # unique key (e.g. fqdn, ip, sha256)
    asset_type: AssetType
    source: str = ""                 # collector that discovered it
    organization: str = ""           # organisation id (from scope.yaml, e.g. "saur_france")
    first_seen: datetime = Field(default_factory=_now)
    last_seen: datetime = Field(default_factory=_now)
    attrs: dict[str, Any] = Field(default_factory=dict)


class Domain(Asset):
    asset_type: AssetType = AssetType.DOMAIN
    fqdn: str = ""
    registrar: str = ""
    whois_org: str = ""
    created: str = ""
    expires: str = ""
    nameservers: list[str] = Field(default_factory=list)


class Subdomain(Asset):
    asset_type: AssetType = AssetType.SUBDOMAIN
    fqdn: str = ""
    parent_domain: str = ""


class IPAddress(Asset):
    asset_type: AssetType = AssetType.IP_ADDRESS
    address: str = ""
    version: int = 4
    asn: int | None = None
    asn_org: str = ""
    country: str = ""


class Certificate(Asset):
    asset_type: AssetType = AssetType.CERTIFICATE
    sha256: str = ""
    serial: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    sans: list[str] = Field(default_factory=list)


class PortService(Asset):
    asset_type: AssetType = AssetType.PORT_SERVICE
    ip: str = ""
    port: int = 0
    protocol: str = "tcp"
    service: str = ""
    product: str = ""
    version: str = ""
    banner: str = ""


class CloudResource(Asset):
    asset_type: AssetType = AssetType.CLOUD_RESOURCE
    provider: str = "azure"
    resource_type: str = ""
    resource_id: str = ""
    name: str = ""
    subscription: str = ""
    resource_group: str = ""


class DNSRecord(Asset):
    asset_type: AssetType = AssetType.DNS_RECORD
    fqdn: str = ""
    rrtype: str = ""
    rdata: str = ""
    ttl: int = 0


# ---------------------------------------------------------------------------
# Relationship
# ---------------------------------------------------------------------------

class Edge(BaseModel):
    source_uid: str
    target_uid: str
    edge_type: EdgeType
    attrs: dict[str, Any] = Field(default_factory=dict)

    @property
    def uid(self) -> str:
        return f"{self.source_uid}|{self.edge_type.value}|{self.target_uid}"


# ---------------------------------------------------------------------------
# Collector result
# ---------------------------------------------------------------------------

class CollectorResult(BaseModel):
    """Returned by each collector after a scan cycle."""
    collector_name: str
    assets: list[Asset] = Field(default_factory=list)
    edges: list[Edge] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    duration_seconds: float = 0.0
