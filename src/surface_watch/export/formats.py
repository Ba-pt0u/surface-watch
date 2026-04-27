"""
json_export.py — Export graph as JSON (node-link format).
graphml.py — Export graph as GraphML.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

import networkx as nx
from networkx.readwrite import json_graph

from surface_watch import config

log = logging.getLogger(__name__)


def export_json(g: nx.DiGraph, output_path: Path | None = None) -> Path:
    """Export graph as JSON node-link format."""
    if output_path is None:
        output_path = config.DATA_DIR / "graph.json"

    data = json_graph.node_link_data(g)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    log.info("[export] JSON exported: %s", output_path)
    return output_path


def export_graphml(g: nx.DiGraph, output_path: Path | None = None) -> Path:
    """Export graph as GraphML (compatible with Gephi, yEd, Neo4j import)."""
    if output_path is None:
        output_path = config.DATA_DIR / "graph.graphml"

    # GraphML doesn't support dict/list/None attributes — flatten or convert them
    g_copy = g.copy()
    for _, attrs in g_copy.nodes(data=True):
        for key, val in list(attrs.items()):
            if val is None:
                attrs[key] = ""
            elif isinstance(val, (dict, list)):
                attrs[key] = json.dumps(val, default=str)
    for _, _, attrs in g_copy.edges(data=True):
        for key, val in list(attrs.items()):
            if val is None:
                attrs[key] = ""
            elif isinstance(val, (dict, list)):
                attrs[key] = json.dumps(val, default=str)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    nx.write_graphml(g_copy, str(output_path))
    log.info("[export] GraphML exported: %s", output_path)
    return output_path
