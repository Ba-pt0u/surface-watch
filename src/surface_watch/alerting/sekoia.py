"""
sekoia.py — Send CEF-formatted alerts to Sekoia.io HTTP intake.

POST events to https://intake.sekoia.io/plain with header X-SEKOIAIO-INTAKE-KEY.
Retry with exponential backoff on transient errors.
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any

import requests

from surface_watch import config
from surface_watch.graph import DiffEntry

log = logging.getLogger(__name__)

_MAX_RETRIES = 5
_BACKOFF_BASE = 2


def _build_cef(
    event_id: str,
    event_name: str,
    severity: int,
    extensions: dict[str, str],
) -> str:
    """Build a CEF-formatted string."""
    # CEF:Version|Device Vendor|Device Product|Device Version|SignatureID|Name|Severity|Extensions
    ext_str = " ".join(f"{k}={v}" for k, v in extensions.items() if v)
    return f"CEF:0|SurfaceWatch|ASM|1.0|{event_id}|{event_name}|{severity}|{ext_str}"


def diff_to_cef(diff: DiffEntry) -> tuple[str, int]:
    """Convert a DiffEntry to a CEF string with appropriate severity."""
    settings = config.SETTINGS.get("alerting", {}).get("severity", {})
    critical_ports = set(config.SETTINGS.get("alerting", {}).get("critical_ports", []))

    # Determine event ID, name, and severity
    if diff.category == "new":
        if diff.asset_type == "subdomain":
            event_id = "NEW_SUBDOMAIN"
            event_name = "New subdomain discovered"
            severity = settings.get("new_subdomain", 5)
        elif diff.asset_type == "ip_address":
            event_id = "NEW_IP"
            event_name = "New IP address discovered"
            severity = settings.get("new_ip", 5)
        elif diff.asset_type == "certificate":
            event_id = "NEW_CERT"
            event_name = "New certificate discovered"
            severity = settings.get("new_certificate", 4)
        elif diff.asset_type == "port_service":
            port = diff.detail.get("port", 0)
            if port in critical_ports:
                event_id = "CRITICAL_PORT"
                event_name = f"Critical port {port} exposed"
                severity = settings.get("critical_port_exposed", 8)
            else:
                event_id = "NEW_PORT"
                event_name = f"New port {port} discovered"
                severity = settings.get("new_port", 6)
        elif diff.asset_type == "cloud_resource":
            event_id = "NEW_CLOUD"
            event_name = "New cloud resource discovered"
            severity = settings.get("new_ip", 5)
        else:
            event_id = "NEW_ASSET"
            event_name = f"New {diff.asset_type} discovered"
            severity = 4
    elif diff.category == "changed":
        event_id = "ASSET_CHANGED"
        event_name = f"{diff.asset_type} changed"
        severity = settings.get("asset_changed", 3)
    elif diff.category == "removed":
        event_id = "ASSET_REMOVED"
        event_name = f"{diff.asset_type} removed"
        severity = settings.get("asset_removed", 2)
    else:
        event_id = "UNKNOWN"
        event_name = "Unknown event"
        severity = 1

    # Build extensions
    extensions: dict[str, str] = {
        "dhost": diff.uid,
        "cs1": diff.asset_type,
        "cs1Label": "assetType",
        "cs2": diff.category,
        "cs2Label": "changeType",
        "cs4": diff.detail.get("organization", ""),
        "cs4Label": "organization",
        "msg": json.dumps(diff.detail, default=str)[:1024],  # truncate long details
        "rt": datetime.now(timezone.utc).strftime("%b %d %Y %H:%M:%S"),
    }

    # Add IP if available
    ip = diff.detail.get("address", diff.detail.get("ip", ""))
    if ip:
        extensions["src"] = ip

    cef = _build_cef(event_id, event_name, severity, extensions)
    return cef, severity


def send_to_sekoia(events: list[str]) -> bool:
    """
    Send CEF events to Sekoia.io HTTP intake.

    Returns True if all events were sent successfully.
    """
    if not config.SEKOIA_INTAKE_KEY:
        log.warning("[sekoia] No intake key configured, writing to local log only")
        return False

    url = config.SEKOIA_INTAKE_URL
    headers = {
        "X-SEKOIAIO-INTAKE-KEY": config.SEKOIA_INTAKE_KEY,
        "Content-Type": "text/plain",
    }
    sekoia_settings = config.SETTINGS.get("sekoia", {})
    batch_size = sekoia_settings.get("batch_size", 50)
    timeout = sekoia_settings.get("timeout", 15)

    session = requests.Session()
    session.headers.update(headers)

    all_ok = True
    for i in range(0, len(events), batch_size):
        batch = events[i:i + batch_size]
        payload = "\n".join(batch)

        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                resp = session.post(url, data=payload, timeout=timeout)
                if resp.status_code in (200, 201, 202):
                    log.debug("[sekoia] Sent %d events (batch %d)", len(batch), i // batch_size + 1)
                    break
                elif resp.status_code == 429:
                    wait = int(resp.headers.get("Retry-After", _BACKOFF_BASE ** attempt))
                    log.warning("[sekoia] Rate limited (429), waiting %ds", wait)
                    time.sleep(wait)
                elif resp.status_code >= 500:
                    wait = _BACKOFF_BASE ** attempt
                    log.warning("[sekoia] Server error %d, retry in %ds", resp.status_code, wait)
                    time.sleep(wait)
                else:
                    log.error("[sekoia] Unexpected status %d: %s", resp.status_code, resp.text[:200])
                    all_ok = False
                    break
            except requests.RequestException as exc:
                if attempt == _MAX_RETRIES:
                    log.error("[sekoia] Failed after %d retries: %s", _MAX_RETRIES, exc)
                    all_ok = False
                    break
                wait = _BACKOFF_BASE ** attempt
                log.warning("[sekoia] Network error (%s), retry in %ds", exc, wait)
                time.sleep(wait)

    return all_ok


def send_realtime_alert(
    event_type: str,
    domain: str,
    scope_domain: str,
    leaf_cert: dict[str, Any],
) -> None:
    """Send a real-time certstream alert to Sekoia."""
    settings = config.SETTINGS.get("alerting", {}).get("severity", {})
    severity = settings.get(event_type, 7)

    extensions = {
        "dhost": domain,
        "cs1": scope_domain,
        "cs1Label": "scopeDomain",
        "cs2": event_type,
        "cs2Label": "alertType",
        "cs3": leaf_cert.get("issuer", {}).get("O", "unknown"),
        "cs3Label": "issuer",
        "msg": f"Certificate issued for {domain} (monitoring {scope_domain})",
        "rt": datetime.now(timezone.utc).strftime("%b %d %Y %H:%M:%S"),
    }

    event_name = "Typosquatting certificate" if event_type == "typosquat_cert" else "New certificate"
    cef = _build_cef(event_type.upper(), event_name, severity, extensions)

    # Also log locally
    _write_local_log(cef)

    if config.SEKOIA_INTAKE_KEY and not config.DRY_RUN:
        send_to_sekoia([cef])


def _write_local_log(cef: str) -> None:
    """Append a CEF event to the local alert log file."""
    log_path = config.DATA_DIR / "alerts.log"
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now(timezone.utc).isoformat()} {cef}\n")


def process_diffs(diffs: list[DiffEntry]) -> int:
    """
    Process diff entries: convert to CEF, send to Sekoia, write local log.
    Returns number of alerts sent.
    """
    if not diffs:
        return 0

    cef_events: list[str] = []
    for diff in diffs:
        cef, severity = diff_to_cef(diff)
        _write_local_log(cef)
        cef_events.append(cef)
        log.info("[alert] %s %s %s (severity=%d)", diff.category.upper(), diff.asset_type, diff.uid, severity)

    if config.DRY_RUN:
        log.info("[alert] DRY_RUN: %d alerts would be sent to Sekoia", len(cef_events))
        return len(cef_events)

    if cef_events:
        send_to_sekoia(cef_events)

    return len(cef_events)
