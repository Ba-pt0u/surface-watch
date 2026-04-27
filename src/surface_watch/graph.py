"""
graph.py — Asset Graph engine.

Wraps NetworkX for in-memory graph operations and SQLite for persistence.
Provides diff detection between scan cycles to generate alerts.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import networkx as nx

from surface_watch.models import Asset, Edge, EdgeType, AssetType

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Diff result
# ---------------------------------------------------------------------------

class DiffEntry:
    __slots__ = ("category", "asset_type", "uid", "detail")

    def __init__(self, category: str, asset_type: str, uid: str, detail: dict[str, Any]):
        self.category = category      # "new", "changed", "removed"
        self.asset_type = asset_type
        self.uid = uid
        self.detail = detail

    def __repr__(self) -> str:
        return f"DiffEntry({self.category}, {self.asset_type}, {self.uid})"


# ---------------------------------------------------------------------------
# SQLite schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    uid         TEXT PRIMARY KEY,
    asset_type  TEXT NOT NULL,
    source      TEXT DEFAULT '',
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    data        TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS edges (
    uid         TEXT PRIMARY KEY,
    source_uid  TEXT NOT NULL,
    target_uid  TEXT NOT NULL,
    edge_type   TEXT NOT NULL,
    data        TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (source_uid) REFERENCES assets(uid),
    FOREIGN KEY (target_uid) REFERENCES assets(uid)
);

CREATE TABLE IF NOT EXISTS scan_runs (
    run_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    collector   TEXT DEFAULT '',
    status      TEXT DEFAULT 'running',
    summary     TEXT DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_edges_source ON edges(source_uid);
CREATE INDEX IF NOT EXISTS idx_edges_target ON edges(target_uid);
"""


class AssetGraph:
    """
    In-memory asset graph backed by SQLite persistence.

    Usage:
        graph = AssetGraph(db_path)
        graph.load()                       # load from SQLite into NetworkX
        graph.ingest(collector_result)      # add assets + edges from a collector
        diffs = graph.diff()               # compare current state vs last snapshot
        graph.save()                       # persist to SQLite
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.g = nx.DiGraph()
        self._db = sqlite3.connect(str(db_path), check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=OFF")  # allow ingesting edges before nodes settle
        self._db.executescript(_SCHEMA)
        self._db.commit()
        self._previous_assets: dict[str, dict] = {}

    # ------------------------------------------------------------------
    # Load / Save
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Load all assets and edges from SQLite into the NetworkX graph."""
        self.g.clear()
        self._previous_assets.clear()

        cur = self._db.execute("SELECT uid, asset_type, source, first_seen, last_seen, data FROM assets")
        for uid, atype, source, first_seen, last_seen, data in cur:
            attrs = json.loads(data)
            attrs.update({
                "asset_type": atype,
                "source": source,
                "first_seen": first_seen,
                "last_seen": last_seen,
            })
            self.g.add_node(uid, **attrs)
            self._previous_assets[uid] = dict(attrs)

        cur = self._db.execute("SELECT uid, source_uid, target_uid, edge_type, data FROM edges")
        for uid, src, tgt, etype, data in cur:
            attrs = json.loads(data)
            attrs["edge_type"] = etype
            attrs["edge_uid"] = uid
            self.g.add_edge(src, tgt, **attrs)

        log.info("Loaded %d assets, %d edges from %s", self.g.number_of_nodes(), self.g.number_of_edges(), self.db_path.name)

    def save(self) -> None:
        """Persist the current graph state to SQLite (full upsert)."""
        now = datetime.now(timezone.utc).isoformat()

        for uid, attrs in self.g.nodes(data=True):
            data = {k: v for k, v in attrs.items() if k not in ("asset_type", "source", "first_seen", "last_seen")}
            self._db.execute(
                """INSERT INTO assets (uid, asset_type, source, first_seen, last_seen, data)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(uid) DO UPDATE SET
                       last_seen = excluded.last_seen,
                       data = excluded.data,
                       source = CASE WHEN excluded.source != '' THEN excluded.source ELSE assets.source END
                """,
                (uid, attrs.get("asset_type", ""), attrs.get("source", ""),
                 attrs.get("first_seen", now), attrs.get("last_seen", now),
                 json.dumps(data, default=str)),
            )

        for src, tgt, attrs in self.g.edges(data=True):
            edge_uid = attrs.get("edge_uid", f"{src}|{attrs.get('edge_type', '')}|{tgt}")
            data = {k: v for k, v in attrs.items() if k not in ("edge_type", "edge_uid")}
            self._db.execute(
                """INSERT INTO edges (uid, source_uid, target_uid, edge_type, data)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(uid) DO UPDATE SET data = excluded.data
                """,
                (edge_uid, src, tgt, attrs.get("edge_type", ""), json.dumps(data, default=str)),
            )

        self._db.commit()
        log.info("Saved %d assets, %d edges", self.g.number_of_nodes(), self.g.number_of_edges())

    # ------------------------------------------------------------------
    # Ingest
    # ------------------------------------------------------------------

    def ingest_asset(self, asset: Asset) -> None:
        """Add or update a single asset in the graph."""
        from surface_watch import config as _cfg  # avoid circular at module level
        now = datetime.now(timezone.utc).isoformat()
        existing = self.g.nodes.get(asset.uid)

        attrs = asset.model_dump(exclude={"uid"}, mode="json")
        attrs["asset_type"] = asset.asset_type.value

        # Auto-assign organization from scope.yaml when not already set
        if not attrs.get("organization"):
            org = _cfg.DOMAIN_TO_ORG.get(asset.uid)  # direct domain match
            if not org:
                # Try to match by parent_domain or suffix
                fqdn = attrs.get("fqdn") or attrs.get("address") or asset.uid
                for domain, o in _cfg.DOMAIN_TO_ORG.items():
                    if fqdn == domain or fqdn.endswith(f".{domain}"):
                        org = o
                        break
            if org:
                attrs["organization"] = org["id"]

        if existing:
            # Preserve first_seen, update last_seen
            # Preserve existing organization if the new asset doesn't have one
            attrs["first_seen"] = existing.get("first_seen", now)
            attrs["last_seen"] = now
            if not attrs.get("organization") and existing.get("organization"):
                attrs["organization"] = existing["organization"]
        else:
            attrs.setdefault("first_seen", now)
            attrs["last_seen"] = now

        self.g.add_node(asset.uid, **attrs)

    def ingest_edge(self, edge: Edge) -> None:
        """Add or update a relationship. Propagates organization from source to target."""
        attrs = edge.model_dump(exclude={"source_uid", "target_uid", "uid"}, mode="json")
        attrs["edge_type"] = edge.edge_type.value
        attrs["edge_uid"] = edge.uid
        self.g.add_edge(edge.source_uid, edge.target_uid, **attrs)

        # Propagate organization from source node to target if target has none
        src_attrs = self.g.nodes.get(edge.source_uid, {})
        tgt_attrs = self.g.nodes.get(edge.target_uid, {})
        if src_attrs.get("organization") and not tgt_attrs.get("organization"):
            self.g.nodes[edge.target_uid]["organization"] = src_attrs["organization"]

    def ingest_result(self, result: "CollectorResult") -> None:
        """Ingest all assets and edges from a CollectorResult."""
        from surface_watch.models import CollectorResult  # avoid circular
        for asset in result.assets:
            self.ingest_asset(asset)
        for edge in result.edges:
            self.ingest_edge(edge)

    # ------------------------------------------------------------------
    # Diff
    # ------------------------------------------------------------------

    def diff(self) -> list[DiffEntry]:
        """
        Compare current graph state against previously loaded state.
        Returns list of DiffEntry for new, changed, and removed assets.
        """
        diffs: list[DiffEntry] = []
        current_uids = set(self.g.nodes)
        previous_uids = set(self._previous_assets.keys())

        # New assets
        for uid in current_uids - previous_uids:
            attrs = dict(self.g.nodes[uid])
            diffs.append(DiffEntry(
                category="new",
                asset_type=attrs.get("asset_type", "unknown"),
                uid=uid,
                detail=attrs,
            ))

        # Removed assets
        for uid in previous_uids - current_uids:
            attrs = self._previous_assets[uid]
            diffs.append(DiffEntry(
                category="removed",
                asset_type=attrs.get("asset_type", "unknown"),
                uid=uid,
                detail=attrs,
            ))

        # Changed assets (compare serialized attributes)
        for uid in current_uids & previous_uids:
            cur = dict(self.g.nodes[uid])
            prev = self._previous_assets[uid]
            # Ignore last_seen changes
            cur_cmp = {k: v for k, v in cur.items() if k != "last_seen"}
            prev_cmp = {k: v for k, v in prev.items() if k != "last_seen"}
            if cur_cmp != prev_cmp:
                changes = {}
                all_keys = set(cur_cmp) | set(prev_cmp)
                for k in all_keys:
                    old_val = prev_cmp.get(k)
                    new_val = cur_cmp.get(k)
                    if old_val != new_val:
                        changes[k] = {"before": old_val, "after": new_val}
                diffs.append(DiffEntry(
                    category="changed",
                    asset_type=cur.get("asset_type", "unknown"),
                    uid=uid,
                    detail={"changes": changes},
                ))

        return diffs

    # ------------------------------------------------------------------
    # Scan run tracking
    # ------------------------------------------------------------------

    def start_run(self, collector: str = "") -> int:
        """Record a scan run start. Returns run_id."""
        now = datetime.now(timezone.utc).isoformat()
        cur = self._db.execute(
            "INSERT INTO scan_runs (started_at, collector) VALUES (?, ?)",
            (now, collector),
        )
        self._db.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def finish_run(self, run_id: int, status: str = "ok", summary: dict | None = None) -> None:
        """Record a scan run completion."""
        now = datetime.now(timezone.utc).isoformat()
        self._db.execute(
            "UPDATE scan_runs SET finished_at = ?, status = ?, summary = ? WHERE run_id = ?",
            (now, status, json.dumps(summary or {}), run_id),
        )
        self._db.commit()

    def get_last_runs(self, limit: int = 20) -> list[dict]:
        """Return recent scan runs."""
        cur = self._db.execute(
            "SELECT run_id, started_at, finished_at, collector, status, summary FROM scan_runs ORDER BY run_id DESC LIMIT ?",
            (limit,),
        )
        return [
            {"run_id": r[0], "started_at": r[1], "finished_at": r[2],
             "collector": r[3], "status": r[4], "summary": json.loads(r[5] or "{}")}
            for r in cur
        ]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self) -> dict:
        """Return counts by asset type, plus per-organisation breakdown."""
        counts: dict = {}
        by_org: dict[str, dict] = {}

        for _, attrs in self.g.nodes(data=True):
            t = attrs.get("asset_type", "unknown")
            counts[t] = counts.get(t, 0) + 1

            org = attrs.get("organization", "")
            if org:
                if org not in by_org:
                    by_org[org] = {}
                by_org[org][t] = by_org[org].get(t, 0) + 1

        counts["edges"] = self.g.number_of_edges()
        counts["total_assets"] = self.g.number_of_nodes()
        counts["by_organization"] = by_org
        return counts

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def get_assets_by_type(self, asset_type: AssetType) -> list[dict]:
        """Return all assets of a given type."""
        return [
            {"uid": uid, **attrs}
            for uid, attrs in self.g.nodes(data=True)
            if attrs.get("asset_type") == asset_type.value
        ]

    def get_all_ips(self) -> set[str]:
        """Return all known IP addresses."""
        return {
            attrs.get("address", uid)
            for uid, attrs in self.g.nodes(data=True)
            if attrs.get("asset_type") == AssetType.IP_ADDRESS.value
        }

    def close(self) -> None:
        self._db.close()
