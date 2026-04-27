"""
test_graph.py — Tests for AssetGraph diff engine and persistence.
"""
import tempfile
from pathlib import Path

import pytest

from surface_watch.graph import AssetGraph
from surface_watch.models import (
    Asset, AssetType, CollectorResult, Domain, Edge, EdgeType, IPAddress, Subdomain,
)


@pytest.fixture
def graph(tmp_path):
    db = tmp_path / "test.db"
    g = AssetGraph(db)
    return g


def test_ingest_asset(graph):
    dom = Domain(uid="example.com", fqdn="example.com", source="test")
    graph.ingest_asset(dom)
    assert "example.com" in graph.g.nodes
    assert graph.g.nodes["example.com"]["asset_type"] == "domain"


def test_ingest_edge(graph):
    dom = Domain(uid="example.com", fqdn="example.com", source="test")
    ip = IPAddress(uid="1.2.3.4", address="1.2.3.4", version=4, source="test")
    edge = Edge(source_uid="example.com", target_uid="1.2.3.4", edge_type=EdgeType.RESOLVES_TO)

    graph.ingest_asset(dom)
    graph.ingest_asset(ip)
    graph.ingest_edge(edge)

    assert graph.g.has_edge("example.com", "1.2.3.4")


def test_ingest_result(graph):
    result = CollectorResult(
        collector_name="test",
        assets=[
            Domain(uid="example.com", fqdn="example.com", source="test"),
            Subdomain(uid="www.example.com", fqdn="www.example.com", parent_domain="example.com", source="test"),
        ],
        edges=[
            Edge(source_uid="example.com", target_uid="www.example.com", edge_type=EdgeType.HAS_SUBDOMAIN),
        ],
    )
    graph.ingest_result(result)
    assert graph.g.number_of_nodes() == 2
    assert graph.g.number_of_edges() == 1


def test_diff_new_assets(graph):
    # Load empty state
    graph.load()

    # Add new assets
    dom = Domain(uid="example.com", fqdn="example.com", source="test")
    graph.ingest_asset(dom)

    diffs = graph.diff()
    assert len(diffs) == 1
    assert diffs[0].category == "new"
    assert diffs[0].uid == "example.com"


def test_diff_removed_assets(graph):
    # Manually set up previous state
    dom = Domain(uid="example.com", fqdn="example.com", source="test")
    graph.ingest_asset(dom)
    graph.save()
    graph.load()  # now example.com is in _previous_assets

    # Remove it from graph
    graph.g.remove_node("example.com")

    diffs = graph.diff()
    assert len(diffs) == 1
    assert diffs[0].category == "removed"


def test_diff_changed_assets(graph):
    dom = Domain(uid="example.com", fqdn="example.com", source="test", registrar="old")
    graph.ingest_asset(dom)
    graph.save()
    graph.load()

    # Change registrar
    dom2 = Domain(uid="example.com", fqdn="example.com", source="test", registrar="new")
    graph.ingest_asset(dom2)

    diffs = graph.diff()
    assert len(diffs) == 1
    assert diffs[0].category == "changed"
    assert "registrar" in diffs[0].detail.get("changes", {})


def test_save_and_load(graph):
    dom = Domain(uid="example.com", fqdn="example.com", source="test")
    ip = IPAddress(uid="1.2.3.4", address="1.2.3.4", version=4, source="test")
    edge = Edge(source_uid="example.com", target_uid="1.2.3.4", edge_type=EdgeType.RESOLVES_TO)

    graph.ingest_asset(dom)
    graph.ingest_asset(ip)
    graph.ingest_edge(edge)
    graph.save()

    # Reload into a fresh graph
    graph2 = AssetGraph(graph.db_path)
    graph2.load()
    assert graph2.g.number_of_nodes() == 2
    assert graph2.g.number_of_edges() == 1
    graph2.close()


def test_stats(graph):
    graph.ingest_asset(Domain(uid="example.com", fqdn="example.com", source="test"))
    graph.ingest_asset(IPAddress(uid="1.2.3.4", address="1.2.3.4", version=4, source="test"))
    stats = graph.stats()
    assert stats["domain"] == 1
    assert stats["ip_address"] == 1
    assert stats["total_assets"] == 2


def test_scan_run_tracking(graph):
    run_id = graph.start_run("test")
    assert run_id >= 1
    graph.finish_run(run_id, status="ok", summary={"assets": 5})
    runs = graph.get_last_runs(1)
    assert len(runs) == 1
    assert runs[0]["status"] == "ok"
    assert runs[0]["summary"]["assets"] == 5
