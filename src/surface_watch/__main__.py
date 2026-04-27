"""
__main__.py — Entry point for surface-watch.

Orchestrates:
  1. APScheduler for periodic collector runs
  2. Certstream real-time listener
  3. Flask web dashboard

Usage:
  python -m surface_watch                  # run all
  python -m surface_watch --dry-run        # no alerts sent
  python -m surface_watch --collector dns  # single collector, then exit
"""
from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
from datetime import datetime, timezone

from surface_watch import config
from surface_watch.graph import AssetGraph

log = logging.getLogger("surface_watch")

# ---------------------------------------------------------------------------
# Collector registry
# ---------------------------------------------------------------------------

_COLLECTOR_CLASSES: dict[str, type] = {}


def _register_collectors() -> None:
    from surface_watch.collectors.dns import DNSCollector
    from surface_watch.collectors.ct import CTBatchCollector
    from surface_watch.collectors.azure import AzureCollector
    from surface_watch.collectors.rdap import RDAPCollector, IPEnrichCollector
    from surface_watch.collectors.portscan import PortScanCollector

    _COLLECTOR_CLASSES["dns"] = DNSCollector
    _COLLECTOR_CLASSES["ct_batch"] = CTBatchCollector
    _COLLECTOR_CLASSES["azure"] = AzureCollector
    _COLLECTOR_CLASSES["rdap"] = RDAPCollector
    _COLLECTOR_CLASSES["portscan"] = PortScanCollector
    _COLLECTOR_CLASSES["ipinfo"] = IPEnrichCollector


# ---------------------------------------------------------------------------
# Run a full scan cycle
# ---------------------------------------------------------------------------

def run_scan_cycle(graph: AssetGraph, collectors: list[str] | None = None) -> None:
    """Execute a full scan cycle: collect → diff → alert → export."""
    from surface_watch.alerting.sekoia import process_diffs
    from surface_watch.export.pyvis_map import generate_map
    from surface_watch.export.formats import export_json, export_graphml

    run_id = graph.start_run(collector=",".join(collectors or ["all"]))
    log.info("=== Scan cycle #%d started ===", run_id)

    active = collectors or ["dns", "ct_batch", "azure", "rdap"]
    errors: list[str] = []

    # Phase 1: Discovery collectors (dns, ct_batch, azure, rdap)
    for name in active:
        if name in ("portscan", "ipinfo"):
            continue  # run after discovery
        cls = _COLLECTOR_CLASSES.get(name)
        if not cls:
            log.warning("Unknown collector: %s", name)
            continue
        collector = cls()
        result = collector.run()
        graph.ingest_result(result)
        errors.extend(result.errors)

    # Phase 2: Port scanner (needs IPs from phase 1)
    if "portscan" in active or collectors is None:
        if "portscan" in _COLLECTOR_CLASSES:
            from surface_watch.collectors.portscan import PortScanCollector
            ps = PortScanCollector()
            ps.set_ips(graph.get_all_ips())
            result = ps.run()
            graph.ingest_result(result)
            errors.extend(result.errors)

    # Phase 3: IP enrichment (needs IPs from phase 1+2)
    if "ipinfo" in active or collectors is None:
        if "ipinfo" in _COLLECTOR_CLASSES:
            from surface_watch.collectors.rdap import IPEnrichCollector
            ie = IPEnrichCollector()
            ie.set_ips(graph.get_all_ips())
            result = ie.run()
            graph.ingest_result(result)
            errors.extend(result.errors)

    # Diff & alert
    diffs = graph.diff()
    alert_count = 0
    if diffs:
        alert_count = process_diffs(diffs)
        log.info("Diff: %d changes → %d alerts", len(diffs), alert_count)
    else:
        log.info("Diff: no changes detected")

    # Save graph to SQLite
    graph.save()

    # Export
    try:
        generate_map(graph.g)
        export_json(graph.g)
        export_graphml(graph.g)
    except Exception as exc:
        log.error("Export error: %s", exc)
        errors.append(f"Export: {exc}")

    # Finalize run
    summary = {
        "assets": graph.g.number_of_nodes(),
        "edges": graph.g.number_of_edges(),
        "diffs": len(diffs),
        "alerts": alert_count,
        "errors": len(errors),
    }
    status = "ok" if not errors else "partial"
    graph.finish_run(run_id, status=status, summary=summary)
    log.info("=== Scan cycle #%d finished (%s) — %d assets, %d edges, %d alerts ===",
             run_id, status, summary["assets"], summary["edges"], alert_count)


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------

def _parse_duration(iso_duration: str) -> dict:
    """Parse ISO 8601 duration like PT6H, PT30M, P1D into APScheduler kwargs."""
    s = iso_duration.upper()
    kwargs: dict = {}
    if s.startswith("P"):
        s = s[1:]
    if "T" in s:
        date_part, time_part = s.split("T", 1)
    else:
        date_part, time_part = s, ""

    # Date part: D
    if "D" in date_part:
        days = int(date_part.split("D")[0])
        kwargs["days"] = days

    # Time part: H, M, S
    rest = time_part
    if "H" in rest:
        h, rest = rest.split("H", 1)
        kwargs["hours"] = int(h)
    if "M" in rest:
        m, rest = rest.split("M", 1)
        kwargs["minutes"] = int(m)
    if "S" in rest:
        secs, rest = rest.split("S", 1)
        kwargs["seconds"] = int(secs)

    return kwargs or {"hours": 6}  # default: 6 hours


def start_scheduler(graph: AssetGraph) -> None:
    """Start APScheduler with configured intervals per collector."""
    from apscheduler.schedulers.background import BackgroundScheduler

    scheduler = BackgroundScheduler(timezone="UTC")
    schedule_config = config.SETTINGS.get("schedule", {})

    for collector_name, interval_str in schedule_config.items():
        if interval_str == "realtime":
            continue  # handled by certstream listener
        try:
            interval_kwargs = _parse_duration(interval_str)
            scheduler.add_job(
                run_scan_cycle,
                "interval",
                args=[graph, [collector_name]],
                id=f"scan_{collector_name}",
                **interval_kwargs,
                max_instances=1,
                coalesce=True,
            )
            log.info("Scheduled %s every %s", collector_name, interval_str)
        except Exception as exc:
            log.error("Failed to schedule %s: %s", collector_name, exc)

    scheduler.start()
    return scheduler


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Surface Watch — Attack Surface Monitor")
    parser.add_argument("--dry-run", action="store_true", help="Disable alerting (simulation mode)")
    parser.add_argument("--collector", type=str, help="Run a single collector then exit")
    parser.add_argument("--no-web", action="store_true", help="Disable the web dashboard")
    parser.add_argument("--no-certstream", action="store_true", help="Disable real-time CT monitoring")
    parser.add_argument("--scan-now", action="store_true", help="Run an immediate full scan before starting scheduler")
    args = parser.parse_args()

    if args.dry_run:
        config.DRY_RUN = True
        log.info("DRY RUN mode — no alerts will be sent")

    # Initialize graph
    graph = AssetGraph(config.DB_PATH)
    graph.load()

    _register_collectors()

    # Single collector mode: run and exit
    if args.collector:
        run_scan_cycle(graph, [args.collector])
        graph.close()
        return

    # Immediate scan if requested
    if args.scan_now:
        run_scan_cycle(graph)

    # Start certstream listener
    if not args.no_certstream:
        from surface_watch.collectors.ct import CTStreamListener
        from surface_watch.alerting.sekoia import send_realtime_alert

        ct_listener = CTStreamListener(callback=send_realtime_alert)
        ct_listener.start()

    # Start scheduler
    scheduler = start_scheduler(graph)

    # Start Flask web dashboard
    if not args.no_web:
        from surface_watch.web.app import create_app, set_graph

        set_graph(graph)
        web_settings = config.SETTINGS.get("web", {})
        host = web_settings.get("host", "0.0.0.0")
        port = web_settings.get("port", 8080)

        flask_app = create_app()
        flask_thread = threading.Thread(
            target=lambda: flask_app.run(host=host, port=port, debug=False, use_reloader=False),
            daemon=True,
            name="flask",
        )
        flask_thread.start()
        log.info("Web dashboard running on http://%s:%d", host, port)

    # Handle graceful shutdown
    stop_event = threading.Event()

    def _shutdown(signum, frame):
        log.info("Shutdown signal received")
        scheduler.shutdown(wait=False)
        graph.close()
        stop_event.set()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    log.info("Surface Watch is running. Press Ctrl+C to stop.")
    stop_event.wait()


if __name__ == "__main__":
    main()
