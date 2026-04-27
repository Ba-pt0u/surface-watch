"""
pyvis_map.py — Generate interactive HTML cartography using pyvis.

Uses cdn_resources="in_line" to embed vis.js directly — works without
internet access or in environments with TLS inspection proxies.

Colour scheme follows Saur brand guidelines:
  - Domain:        #003B5C (Corporate Blue)
  - Subdomain:     #00B2A9 (Glacier Turquoise)
  - IP Address:    #FFCD00 (Horizon Yellow)
  - Certificate:   #9595D2 (Lake Lilac)
  - Port/Service:  #E87722 (Orange)
  - Cloud Resource:#4CAF50 (Green)
  DNS records are hidden from the map (too noisy — still in the graph DB).
"""
from __future__ import annotations

import logging
from pathlib import Path

import networkx as nx
from pyvis.network import Network

from surface_watch import config

log = logging.getLogger(__name__)

# Saur brand colours — matches PROJECT.md ADR-007 and UI-SAUR/organisation.yaml
_COLOURS = {
    "domain":         {"background": "#003B5C", "border": "#002a42", "highlight": {"background": "#004d7a", "border": "#002a42"}},
    "subdomain":      {"background": "#00B2A9", "border": "#008f88", "highlight": {"background": "#00cfc5", "border": "#008f88"}},
    "ip_address":     {"background": "#FFCD00", "border": "#ccaa00", "highlight": {"background": "#ffe033", "border": "#ccaa00"}},
    "certificate":    {"background": "#9595D2", "border": "#7070bb", "highlight": {"background": "#ababde", "border": "#7070bb"}},
    "port_service":   {"background": "#E87722", "border": "#c45c0a", "highlight": {"background": "#f0954a", "border": "#c45c0a"}},
    "cloud_resource": {"background": "#4CAF50", "border": "#388e3c", "highlight": {"background": "#66bb6a", "border": "#388e3c"}},
}

_SHAPES = {
    "domain":         "diamond",
    "subdomain":      "dot",
    "ip_address":     "square",
    "certificate":    "triangleDown",
    "port_service":   "star",
    "cloud_resource": "hexagon",
}

# Node types to exclude from the visual map (still in graph DB)
_HIDDEN_TYPES = {"dns_record"}

# Tree depth levels for hierarchical layout (domain at root = 0)
_LEVELS = {
    "domain":         0,
    "subdomain":      1,
    "cloud_resource": 1,
    "ip_address":     2,
    "certificate":    2,
    "port_service":   3,
}

_LEGEND_HTML_TPL = """
<div id="sw-overlay" style="
    position:fixed; top:12px; left:12px; z-index:9999;
    background:rgba(0,0,0,0.82); color:#fff;
    border-radius:10px; padding:14px 18px;
    font-family:Arial,sans-serif; font-size:12px;
    min-width:185px; box-shadow:0 4px 18px rgba(0,0,0,0.4);
    user-select:none;
">
  <div style="font-weight:700;font-size:13px;margin-bottom:10px;letter-spacing:.5px;">
    &#x1F5FA; Surface Watch
  </div>

  <!-- Asset types -->
  <div style="font-size:10px;text-transform:uppercase;letter-spacing:.8px;color:rgba(255,255,255,.45);margin-bottom:5px;">Types d'asset</div>
  <div style="display:flex;flex-direction:column;gap:4px;margin-bottom:10px;">
    <div><span style="display:inline-block;width:11px;height:11px;background:#003B5C;border-radius:2px;margin-right:6px;"></span>Domain</div>
    <div><span style="display:inline-block;width:11px;height:11px;background:#00B2A9;border-radius:50%;margin-right:6px;"></span>Subdomain</div>
    <div><span style="display:inline-block;width:11px;height:11px;background:#FFCD00;border-radius:2px;margin-right:6px;"></span>IP Address</div>
    <div><span style="display:inline-block;width:11px;height:11px;background:#9595D2;border-radius:2px;margin-right:6px;"></span>Certificate</div>
    <div><span style="display:inline-block;width:11px;height:11px;background:#E87722;border-radius:50%;margin-right:6px;"></span>Port / Service</div>
    <div><span style="display:inline-block;width:11px;height:11px;background:#4CAF50;border-radius:2px;margin-right:6px;"></span>Cloud Resource</div>
  </div>

  <!-- Organisations -->
  {org_legend}

  <hr style="border:none;border-top:1px solid rgba(255,255,255,.2);margin:8px 0;">
  <div id="sw-stats" style="color:rgba(255,255,255,.7);font-size:11px;"></div>
  <a href="/" style="
    display:block;margin-top:10px;padding:6px 10px;text-align:center;
    background:#00B2A9;color:#fff;border-radius:6px;text-decoration:none;
    font-weight:600;font-size:11px;letter-spacing:.3px;
  ">&#8592; Dashboard</a>
</div>
<script>
document.addEventListener('DOMContentLoaded', function() {
  var el = document.getElementById('sw-stats');
  if (el && typeof network !== 'undefined') {
    var n = network.body.data.nodes.length;
    var e = network.body.data.edges.length;
    el.textContent = n + ' assets · ' + e + ' relations';
  }
});
</script>
"""


def _build_legend_html(orgs: list[dict]) -> str:
    """Build the legend HTML, including an org section if multiple orgs are configured."""
    if len(orgs) <= 1:
        return _LEGEND_HTML_TPL.replace("{org_legend}", "")

    rows = '\n'.join(
        f'<div><span style="display:inline-block;width:11px;height:2px;'
        f'background:{o["brand_color"]};margin-right:6px;vertical-align:middle;"></span>'
        f'{o["name"]}</div>'
        for o in orgs
    )
    org_section = (
        '<div style="font-size:10px;text-transform:uppercase;letter-spacing:.8px;'
        'color:rgba(255,255,255,.45);margin-bottom:5px;">Organisations</div>'
        f'<div style="display:flex;flex-direction:column;gap:4px;margin-bottom:10px;">{rows}</div>'
    )
    return _LEGEND_HTML_TPL.replace("{org_legend}", org_section)


def generate_map(g: nx.DiGraph, output_path: Path | None = None) -> Path:
    """
    Generate a self-contained interactive pyvis HTML map.

    All JS is embedded inline (cdn_resources="in_line") — no CDN needed.
    DNS record nodes are hidden to keep the graph readable.
    Returns the path to the generated HTML file.
    """
    if output_path is None:
        output_path = config.DATA_DIR / "map.html"

    # Build a filtered view: exclude noisy dns_record nodes
    visible = nx.DiGraph()
    for uid, attrs in g.nodes(data=True):
        if attrs.get("asset_type") not in _HIDDEN_TYPES:
            visible.add_node(uid, **attrs)
    for src, tgt, attrs in g.edges(data=True):
        if src in visible.nodes and tgt in visible.nodes:
            visible.add_edge(src, tgt, **attrs)

    net = Network(
        height="100vh",
        width="100%",
        directed=True,
        bgcolor="#0f1117",
        font_color="#e8e8e8",
        select_menu=False,
        filter_menu=False,
        cdn_resources="in_line",   # embed vis.js — no CDN needed
    )
    net.set_options("""
    {
      "layout": {
        "hierarchical": {
          "enabled": true,
          "direction": "UD",
          "sortMethod": "directed",
          "levelSeparation": 160,
          "nodeSpacing": 130,
          "treeSpacing": 220,
          "blockShifting": true,
          "edgeMinimization": true,
          "parentCentralization": true
        }
      },
      "physics": { "enabled": false },
      "interaction": {
        "hover": true,
        "tooltipDelay": 100,
        "navigationButtons": true,
        "keyboard": { "enabled": true },
        "zoomView": true,
        "dragView": true
      },
      "edges": {
        "smooth": { "type": "cubicBezier", "forceDirection": "vertical", "roundness": 0.4 },
        "font": { "size": 9, "color": "rgba(200,200,200,0.55)", "strokeWidth": 0, "align": "middle" },
        "labelHighlightBold": false
      },
      "nodes": {
        "font": { "size": 12, "face": "Arial" }
      }
    }
    """)

    # Build org colour lookup from config (id -> brand_color)
    org_colors: dict[str, str] = {o["id"]: o["brand_color"] for o in config.ORGANIZATIONS}

    for uid, attrs in visible.nodes(data=True):
        asset_type = attrs.get("asset_type", "unknown")
        base_colour = _COLOURS.get(asset_type, {"background": "#888", "border": "#555"})
        shape = _SHAPES.get(asset_type, "dot")

        # Override border with org brand colour when available
        org_id = attrs.get("organization", "")
        org_border = org_colors.get(org_id)
        if org_border:
            colour = dict(base_colour)  # shallow copy
            colour["border"] = org_border
            colour["highlight"] = {**base_colour.get("highlight", {}), "border": org_border}
        else:
            colour = base_colour

        degree = visible.degree(uid)
        size = min(55, max(14, 12 + degree * 4))

        # Tooltip: concise key facts
        lines = [f"<b style='font-size:13px'>{uid}</b>", f"<i>{asset_type}</i>"]
        if org_id:
            org_name = next((o["name"] for o in config.ORGANIZATIONS if o["id"] == org_id), org_id)
            lines.append(f"<span style='color:{org_border or '#aaa'}'>{org_name}</span>")
        lines.append("")
        skip = {"asset_type", "attrs", "first_seen", "last_seen", "uid", "organization"}
        for k, v in attrs.items():
            if k in skip or not v:
                continue
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v) if v else ""
            lines.append(f"<b>{k}:</b> {v}")
        tooltip = "<br>".join(lines)

        label = uid if len(uid) <= 35 else uid[:32] + "…"

        net.add_node(
            uid,
            label=label,
            title=tooltip,
            color=colour,
            shape=shape,
            size=size,
            group=asset_type,
            level=_LEVELS.get(asset_type, 2),
            font={"color": "#ffffff" if asset_type in ("domain", "subdomain", "port_service", "cloud_resource") else "#333333"},
        )

    for src, tgt, attrs in visible.edges(data=True):
        edge_type = attrs.get("edge_type", "").replace("_", " ").lower()
        net.add_edge(
            src, tgt,
            label=edge_type,
            title=edge_type,
            arrows={"to": {"enabled": True, "scaleFactor": 0.6}},
            color={"color": "rgba(150,150,170,0.45)", "highlight": "#00B2A9"},
            width=1.5,
            font={"size": 9, "color": "rgba(180,180,200,0.65)", "strokeWidth": 0},
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    # Use generate_html() + explicit UTF-8 write to avoid cp1252 issues on Windows
    # (write_html() uses the system locale which may not handle vis.js Unicode chars)
    html_content = net.generate_html(notebook=False)
    output_path.write_text(html_content, encoding="utf-8")

    # Post-process: fix body styles and inject legend overlay
    legend_html = _build_legend_html(config.ORGANIZATIONS)
    _inject_chrome(output_path, legend_html)

    log.info(
        "[export] Map generated: %s (%d visible nodes, %d edges, %d dns_records hidden)",
        output_path, visible.number_of_nodes(), visible.number_of_edges(),
        g.number_of_nodes() - visible.number_of_nodes(),
    )
    return output_path


def _inject_chrome(path: Path, legend_html: str) -> None:
    """Post-process pyvis HTML: full-page layout + legend overlay."""
    content = path.read_text(encoding="utf-8")

    css = """<style>
html, body {
    margin: 0; padding: 0;
    width: 100%; height: 100%;
    overflow: hidden;
    background: #0f1117;
}
/* pyvis wraps #mynetwork in a .card div — make both fill the viewport */
body > .card {
    width: 100% !important;
    height: 100vh !important;
    margin: 0 !important;
    padding: 0 !important;
    border: none !important;
    border-radius: 0 !important;
    background: #0f1117 !important;
}
#mynetwork {
    width: 100% !important;
    height: 100vh !important;
    border: none !important;
    background: #0f1117 !important;
}
/* Hide any pyvis headings if present */
h1, h2, h3, .card-title { display: none !important; }
/* select/filter menus if pyvis still renders them */
.vis-manipulation { display: none !important; }
</style>"""

    content = content.replace("</head>", f"{css}\n</head>", 1)
    content = content.replace("</body>", f"{legend_html}\n</body>", 1)
    path.write_text(content, encoding="utf-8")
