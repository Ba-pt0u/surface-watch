"""
app.py — Flask web dashboard.

Routes:
  GET /              — Dashboard: stats, recent alerts, collector status
  GET /assets        — Asset browser (filterable by type)
  GET /scans         — Scan history with discovery counts
  GET /scans/<id>    — Scan detail
  GET /config          — Configuration page (scope, settings, collector status)
  GET /map           — Full-page Cytoscape.js cartography (3 layouts, live data)
  GET /api/stats     — JSON stats
  GET /api/alerts    — JSON recent alerts (structured, parsed from CEF)
  GET /api/assets    — JSON asset list (filterable)
  GET /api/scan/status  — JSON current scan status (running/idle)
  GET /api/graph.json    — Cytoscape.js-compatible live graph JSON
  GET /api/graph.graphml — Download GraphML export
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file

from surface_watch import config

log = logging.getLogger(__name__)

_app = Flask(
    __name__,
    template_folder=str(Path(__file__).parent / "templates"),
    static_folder=str(Path(__file__).parent / "static"),
)

# Set by __main__.py after graph is initialized
_graph = None
_scheduler = None
_trigger_callback = None


def set_graph(graph: "AssetGraph") -> None:
    global _graph
    _graph = graph


def set_scheduler(scheduler) -> None:
    global _scheduler
    _scheduler = scheduler


def set_trigger_callback(fn) -> None:
    """Register the run_scan_cycle function to avoid circular import."""
    global _trigger_callback
    _trigger_callback = fn


# Basic input validators for config endpoints
_DOMAIN_RE = re.compile(r'^[a-zA-Z0-9*._-]+$')
_CIDR_RE   = re.compile(r'^[0-9a-fA-F:.]+(/\d+)?$')
_HEX_RE    = re.compile(r'^#[0-9a-fA-F]{3,6}$')
_ISO_DUR_RE = re.compile(r'^P(\d+D)?(T(\d+H)?(\d+M)?(\d+S)?)?$|^realtime$', re.IGNORECASE)


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

@_app.route("/")
def dashboard():
    stats = _graph.stats() if _graph else {}
    runs = _graph.get_last_runs(10) if _graph else []

    # Organization filter from query string
    org_filter = request.args.get("org", "")
    alerts = _read_recent_alerts(50, org_filter=org_filter)

    map_exists = bool(_graph and _graph.g.number_of_nodes() > 0)
    return render_template(
        "dashboard.html",
        stats=stats,
        runs=runs,
        alerts=alerts,
        organizations=config.ORGANIZATIONS,
        active_org=org_filter,
        map_exists=map_exists,
        now=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )


@_app.route("/assets")
def assets_view():
    asset_type = request.args.get("type", "")
    search = request.args.get("q", "").strip().lower()
    if not _graph:
        assets = []
    else:
        assets = [
            {"uid": uid, **attrs}
            for uid, attrs in _graph.g.nodes(data=True)
            if (not asset_type or attrs.get("asset_type") == asset_type)
            and (not search or search in uid.lower())
        ]
        assets.sort(key=lambda a: (a.get("asset_type", ""), a.get("uid", "")))

    # Count per type for sidebar
    type_counts: dict = {}
    if _graph:
        for _, attrs in _graph.g.nodes(data=True):
            t = attrs.get("asset_type", "")
            type_counts[t] = type_counts.get(t, 0) + 1

    return render_template(
        "assets.html",
        assets=assets,
        asset_type=asset_type,
        search=search,
        type_counts=type_counts,
        now=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )


@_app.route("/scans")
def scans_view():
    runs = _graph.get_last_runs(50) if _graph else []
    return render_template(
        "scans.html",
        runs=runs,
        now=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )


@_app.route("/scans/<int:run_id>")
def scan_detail(run_id: int):
    if not _graph:
        return render_template("scans.html", runs=[], now=""), 404
    runs = _graph.get_last_runs(200)
    run = next((r for r in runs if r["run_id"] == run_id), None)
    if not run:
        return render_template("scans.html", runs=[], now=""), 404
    return render_template(
        "scan_detail.html",
        run=run,
        now=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )


@_app.route("/map")
def map_view():
    """Interactive Cytoscape.js cartography (live from in-memory graph)."""
    if not _graph or _graph.g.number_of_nodes() == 0:
        return render_template("map_empty.html")
    _HIDDEN = {"dns_record"}
    node_count = sum(1 for _, a in _graph.g.nodes(data=True) if a.get("asset_type") not in _HIDDEN)
    edge_count = sum(
        1 for s, t, _ in _graph.g.edges(data=True)
        if _graph.g.nodes.get(s, {}).get("asset_type") not in _HIDDEN
        and _graph.g.nodes.get(t, {}).get("asset_type") not in _HIDDEN
    )
    return render_template(
        "map.html",
        node_count=node_count,
        edge_count=edge_count,
        organizations=config.ORGANIZATIONS,
    )


@_app.route("/config")
def config_view():
    """Configuration page: collector status, scope editor, settings editor."""
    excl = config.SCOPE.get("exclusions") or {}
    return render_template(
        "config.html",
        organizations=config.ORGANIZATIONS,
        settings=config.SETTINGS,
        exc_domains=(excl.get("domains") or []),
        exc_ip_ranges=(excl.get("ip_ranges") or []),
        azure_enabled=config.AZURE_ENABLED,
        dry_run=config.DRY_RUN,
    )


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

@_app.route("/api/stats")
def api_stats():
    if not _graph:
        return jsonify({"error": "Graph not initialized"}), 503
    stats = _graph.stats()
    stats["last_runs"] = _graph.get_last_runs(5)
    stats["organizations"] = config.ORGANIZATIONS
    return jsonify(stats)


@_app.route("/api/alerts")
def api_alerts():
    limit = request.args.get("limit", 100, type=int)
    org_filter = request.args.get("org", "")
    alerts = _read_recent_alerts(limit, org_filter=org_filter)
    return jsonify(alerts)


@_app.route("/api/assets")
def api_assets():
    asset_type = request.args.get("type", "")
    search = request.args.get("q", "").strip().lower()
    if not _graph:
        return jsonify([])
    assets = [
        {"uid": uid, **attrs}
        for uid, attrs in _graph.g.nodes(data=True)
        if (not asset_type or attrs.get("asset_type") == asset_type)
        and (not search or search in uid.lower())
    ]
    assets.sort(key=lambda a: a.get("uid", ""))
    return jsonify(assets)


@_app.route("/api/scan/status")
def api_scan_status():
    """Return whether a scan is currently running (checks for runs with no finished_at)."""
    if not _graph:
        return jsonify({"running": False})
    cur = _graph._db.execute(
        "SELECT run_id, started_at, collector FROM scan_runs WHERE finished_at IS NULL ORDER BY run_id DESC LIMIT 1"
    )
    row = cur.fetchone()
    if row:
        return jsonify({"running": True, "run_id": row[0], "started_at": row[1], "collector": row[2]})
    return jsonify({"running": False})


@_app.route("/api/graph.json")
def api_graph_json():
    """Cytoscape.js-compatible graph JSON (live from in-memory graph)."""
    if not _graph:
        return jsonify({"elements": []})
    _HIDDEN = {"dns_record"}
    org_colors = {o["id"]: o["brand_color"] for o in config.ORGANIZATIONS}
    elements = []
    for uid, attrs in _graph.g.nodes(data=True):
        if attrs.get("asset_type") in _HIDDEN:
            continue
        degree = _graph.g.degree(uid)
        label = uid if len(uid) <= 30 else uid[:27] + "\u2026"
        skip = {"asset_type", "first_seen", "last_seen", "uid", "organization", "source"}
        node_data = {
            "id":        uid,
            "label":     label,
            "type":      attrs.get("asset_type", "unknown"),
            "org":       attrs.get("organization", ""),
            "org_color": org_colors.get(attrs.get("organization", ""), ""),
            "source":    attrs.get("source", ""),
            "degree":    degree,
        }
        for k, v in attrs.items():
            if k not in skip and v:
                if isinstance(v, list):
                    v = ", ".join(str(x) for x in v) if v else ""
                node_data[f"attr_{k}"] = str(v)
        elements.append({"data": node_data})
    for src, tgt, edge_attrs in _graph.g.edges(data=True):
        src_type = _graph.g.nodes.get(src, {}).get("asset_type")
        tgt_type = _graph.g.nodes.get(tgt, {}).get("asset_type")
        if src_type in _HIDDEN or tgt_type in _HIDDEN:
            continue
        edge_uid = edge_attrs.get("edge_uid", f"{src}|{edge_attrs.get('edge_type', 'x')}|{tgt}")
        elements.append({"data": {
            "id":     edge_uid,
            "source": src,
            "target": tgt,
            "label":  edge_attrs.get("edge_type", "").replace("_", " "),
        }})
    return jsonify({"elements": elements})


@_app.route("/api/graph.graphml")
def api_graph_graphml():
    path = config.DATA_DIR / "graph.graphml"
    if not path.exists():
        return jsonify({"error": "No export yet"}), 404
    return send_file(str(path), mimetype="application/xml", as_attachment=True)


# ---------------------------------------------------------------------------
# Config API
# ---------------------------------------------------------------------------

@_app.route("/api/collector/status")
def api_collector_status():
    """Return status of each collector: running / standby / realtime / disabled."""
    # Collect running collectors from DB
    running: set[str] = set()
    if _graph:
        cur = _graph._db.execute(
            "SELECT collector FROM scan_runs WHERE finished_at IS NULL"
        )
        for row in cur:
            for c in (row[0] or "").split(","):
                running.add(c.strip())

    # Collect scheduler next-run times
    job_next: dict[str, str | None] = {}
    if _scheduler:
        for job in _scheduler.get_jobs():
            nrt = job.next_run_time
            job_next[job.id] = nrt.isoformat() if nrt else None

    schedule_cfg = config.SETTINGS.get("schedule", {})
    all_names = ["dns", "ct_batch", "ct_stream", "azure", "rdap", "portscan", "ipinfo"]
    collectors = []
    for name in all_names:
        interval = schedule_cfg.get(name, "")
        if interval == "realtime":
            status = "realtime"
        elif name == "azure" and not config.AZURE_ENABLED:
            status = "disabled"
        elif name in running:
            status = "running"
        elif f"scan_{name}" in job_next:
            status = "standby"
        else:
            status = "not_scheduled"
        collectors.append({
            "name":     name,
            "status":   status,
            "schedule": interval,
            "next_run": job_next.get(f"scan_{name}"),
        })
    return jsonify(collectors)


@_app.route("/api/config/scope", methods=["POST"])
def api_config_scope():
    """Validate and save scope.yaml."""
    import copy as _copy
    import yaml as _yaml

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Corps JSON manquant"}), 400

    organizations = []
    for org in data.get("organizations", []):
        oid   = str(org.get("id", "")).strip()[:64]
        name  = str(org.get("name", oid)).strip()[:128]
        color = str(org.get("brand_color", "#003B5C")).strip()
        if not oid:
            continue
        if not _HEX_RE.match(color):
            color = "#003B5C"
        domains   = [d.strip() for d in org.get("domains",   []) if _DOMAIN_RE.match(d.strip())]
        ip_ranges = [r.strip() for r in org.get("ip_ranges", []) if _CIDR_RE.match(r.strip())]
        organizations.append({"id": oid, "name": name, "brand_color": color,
                               "domains": domains, "ip_ranges": ip_ranges})

    excl = data.get("exclusions", {})
    exc_domains   = [d.strip() for d in excl.get("domains",   []) if _DOMAIN_RE.match(d.strip())]
    exc_ip_ranges = [r.strip() for r in excl.get("ip_ranges", []) if _CIDR_RE.match(r.strip())]

    new_scope = {"organizations": organizations,
                 "exclusions": {"domains": exc_domains, "ip_ranges": exc_ip_ranges}}
    try:
        (config.CONFIG_DIR / "scope.yaml").write_text(
            _yaml.safe_dump(new_scope, allow_unicode=True, default_flow_style=False),
            encoding="utf-8",
        )
    except Exception as exc:
        log.error("scope.yaml write error: %s", exc)
        return jsonify({"error": str(exc)}), 500
    return jsonify({"ok": True, "msg": "scope.yaml sauvegardé — redémarrez pour appliquer."})


@_app.route("/api/config/settings", methods=["POST"])
def api_config_settings():
    """Validate and save settings.yaml."""
    import copy as _copy
    import yaml as _yaml

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Corps JSON manquant"}), 400

    new = _copy.deepcopy(config.SETTINGS)

    for name, val in data.get("schedule", {}).items():
        val = str(val).strip()
        if name in new.get("schedule", {}) and _ISO_DUR_RE.match(val):
            new["schedule"][name] = val

    ps = data.get("portscan", {})
    if "top_ports" in ps:
        new["portscan"]["top_ports"] = max(1, min(65535, int(ps["top_ports"])))
    if "timeout" in ps:
        new["portscan"]["timeout"] = max(10, min(3600, int(ps["timeout"])))

    for k, v in data.get("alerting", {}).get("severity", {}).items():
        if k in new.get("alerting", {}).get("severity", {}):
            new["alerting"]["severity"][k] = max(0, min(10, int(v)))

    if "critical_ports" in data:
        new["alerting"]["critical_ports"] = [
            int(p) for p in data["critical_ports"] if str(p).isdigit()
        ]

    try:
        (config.CONFIG_DIR / "settings.yaml").write_text(
            _yaml.safe_dump(new, allow_unicode=True, default_flow_style=False),
            encoding="utf-8",
        )
    except Exception as exc:
        log.error("settings.yaml write error: %s", exc)
        return jsonify({"error": str(exc)}), 500
    return jsonify({"ok": True, "msg": "settings.yaml sauvegardé — redémarrez pour appliquer les fréquences."})


@_app.route("/api/collector/<name>/trigger", methods=["POST"])
def api_collector_trigger(name: str):
    """Trigger an immediate run of a single collector."""
    import threading as _threading
    allowed = {"dns", "ct_batch", "azure", "rdap", "portscan", "ipinfo"}
    if name not in allowed:
        return jsonify({"error": "Collecteur inconnu"}), 400
    if not _graph:
        return jsonify({"error": "Graph non initialisé"}), 503
    if not _trigger_callback:
        return jsonify({"error": "Service non prêt"}), 503
    # Prevent concurrent scans
    row = _graph._db.execute(
        "SELECT 1 FROM scan_runs WHERE finished_at IS NULL LIMIT 1"
    ).fetchone()
    if row:
        return jsonify({"error": "Un scan est déjà en cours"}), 409
    _threading.Thread(
        target=_trigger_callback,
        args=[_graph, [name]],
        daemon=True,
        name=f"manual_{name}",
    ).start()
    return jsonify({"ok": True, "msg": f"Collecteur {name} déclenché."})


# ---------------------------------------------------------------------------
# Alert helpers
# ---------------------------------------------------------------------------

_CEF_RE = re.compile(
    r"CEF:0\|[^|]+\|[^|]+\|[^|]+\|(?P<event_id>[^|]+)\|(?P<event_name>[^|]+)\|(?P<severity>\d+)\|(?P<ext>.*)"
)
_EXT_KEY_RE = re.compile(r'(\w+)=(".*?(?<!\\)"|[^ ]+)')


def _parse_cef(line: str) -> dict:
    """Parse a CEF line into a structured dict."""
    # line format: ISO_TIMESTAMP CEF:0|...
    parts = line.split(" ", 1)
    timestamp = parts[0] if len(parts) == 2 else ""
    cef_raw = parts[1] if len(parts) == 2 else line

    result = {
        "timestamp": timestamp,
        "cef_raw": cef_raw,
        "event_id": "",
        "event_name": "",
        "severity": 0,
        "asset": "",
        "org": "",
    }

    m = _CEF_RE.match(cef_raw)
    if not m:
        return result

    result["event_id"] = m.group("event_id")
    result["event_name"] = m.group("event_name")
    result["severity"] = int(m.group("severity"))

    # Parse extensions
    ext_str = m.group("ext")
    for km in _EXT_KEY_RE.finditer(ext_str):
        key, val = km.group(1), km.group(2).strip('"')
        if key == "dhost":
            result["asset"] = val
        elif key == "src" and not result["asset"]:
            result["asset"] = val
        elif key == "cs4":          # organization id
            result["org"] = val

    return result


def _sev_class(severity: int) -> str:
    """Map CEF severity to CSS class."""
    if severity >= 8:
        return "sev-critical"
    if severity >= 6:
        return "sev-high"
    if severity >= 4:
        return "sev-medium"
    return "sev-low"


def _read_recent_alerts(limit: int = 100, org_filter: str = "") -> list[dict]:
    """Read and parse the last N alerts from the local log file, optionally filtered by org."""
    log_path = config.DATA_DIR / "alerts.log"
    if not log_path.exists():
        return []

    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    recent = lines[-limit * 3 if org_filter else -limit:]  # over-read when filtering
    recent.reverse()

    alerts = []
    for line in recent:
        if not line.strip():
            continue
        parsed = _parse_cef(line)
        parsed["sev_class"] = _sev_class(parsed["severity"])
        # Org filtering: CEF extension cs4 carries org id
        if org_filter and parsed.get("org", "") != org_filter:
            continue
        alerts.append(parsed)
        if len(alerts) >= limit:
            break
    return alerts


def create_app() -> Flask:
    return _app
