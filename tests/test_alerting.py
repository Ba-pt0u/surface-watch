"""
test_alerting.py — Tests for CEF formatting and diff-to-alert conversion.
"""
import pytest

from surface_watch.alerting.sekoia import _build_cef, diff_to_cef
from surface_watch.graph import DiffEntry


def test_build_cef():
    cef = _build_cef("TEST_001", "Test Event", 5, {"src": "1.2.3.4", "dhost": "example.com"})
    assert cef.startswith("CEF:0|SurfaceWatch|ASM|1.0|TEST_001|Test Event|5|")
    assert "src=1.2.3.4" in cef
    assert "dhost=example.com" in cef


def test_diff_to_cef_new_subdomain():
    diff = DiffEntry("new", "subdomain", "www.example.com", {"fqdn": "www.example.com"})
    cef, severity = diff_to_cef(diff)
    assert "NEW_SUBDOMAIN" in cef
    assert severity >= 4


def test_diff_to_cef_new_port():
    diff = DiffEntry("new", "port_service", "1.2.3.4:tcp/80", {"port": 80, "ip": "1.2.3.4"})
    cef, severity = diff_to_cef(diff)
    assert "NEW_PORT" in cef


def test_diff_to_cef_critical_port():
    diff = DiffEntry("new", "port_service", "1.2.3.4:tcp/22", {"port": 22, "ip": "1.2.3.4"})
    cef, severity = diff_to_cef(diff)
    assert "CRITICAL_PORT" in cef
    assert severity >= 7


def test_diff_to_cef_changed():
    diff = DiffEntry("changed", "ip_address", "1.2.3.4", {"changes": {"asn": {"before": 100, "after": 200}}})
    cef, severity = diff_to_cef(diff)
    assert "ASSET_CHANGED" in cef


def test_diff_to_cef_removed():
    diff = DiffEntry("removed", "domain", "old.example.com", {})
    cef, severity = diff_to_cef(diff)
    assert "ASSET_REMOVED" in cef
    assert severity <= 3
