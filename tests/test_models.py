"""
test_models.py — Tests for Pydantic data models.
"""
from surface_watch.models import (
    Asset, AssetType, Certificate, CollectorResult, Domain, Edge, EdgeType,
    IPAddress, PortService, Subdomain,
)


def test_domain_model():
    d = Domain(uid="example.com", fqdn="example.com", source="dns")
    assert d.asset_type == AssetType.DOMAIN
    assert d.uid == "example.com"


def test_subdomain_model():
    s = Subdomain(uid="www.example.com", fqdn="www.example.com", parent_domain="example.com")
    assert s.asset_type == AssetType.SUBDOMAIN


def test_ip_model():
    ip = IPAddress(uid="1.2.3.4", address="1.2.3.4", version=4)
    assert ip.asset_type == AssetType.IP_ADDRESS


def test_certificate_model():
    cert = Certificate(
        uid="cert:abc123", sha256="abc123", serial="123",
        issuer="Let's Encrypt", sans=["example.com", "www.example.com"],
    )
    assert cert.asset_type == AssetType.CERTIFICATE
    assert len(cert.sans) == 2


def test_port_service_model():
    ps = PortService(uid="1.2.3.4:tcp/443", ip="1.2.3.4", port=443, service="https")
    assert ps.asset_type == AssetType.PORT_SERVICE


def test_edge_uid():
    edge = Edge(source_uid="example.com", target_uid="1.2.3.4", edge_type=EdgeType.RESOLVES_TO)
    assert edge.uid == "example.com|resolves_to|1.2.3.4"


def test_collector_result():
    result = CollectorResult(
        collector_name="test",
        assets=[Domain(uid="example.com", fqdn="example.com")],
        edges=[],
    )
    assert len(result.assets) == 1
    assert result.collector_name == "test"
