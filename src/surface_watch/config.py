"""
config.py — Centralized configuration from .env, scope.yaml, settings.yaml
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import yaml
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_ROOT = Path(__file__).resolve().parent.parent.parent  # surface-watch/
_CONFIG_DIR = Path(os.getenv("SW_CONFIG_DIR", str(_ROOT / "config")))
_DATA_DIR = Path(os.getenv("SW_DATA_DIR", str(_ROOT / "data")))

load_dotenv(_ROOT / ".env")


def _require(name: str) -> str:
    """Return env var value or exit with an explicit error."""
    value = os.getenv(name)
    if not value:
        print(f"[ERROR] Environment variable '{name}' is missing or empty.")
        print(f"        Copy .env.example to .env and fill in all values.")
        sys.exit(1)
    return value


def _optional(name: str, default: str = "") -> str:
    return os.getenv(name, default)


# ---------------------------------------------------------------------------
# YAML configs
# ---------------------------------------------------------------------------
def _load_yaml(filename: str) -> dict:
    path = _CONFIG_DIR / filename
    if not path.exists():
        print(f"[ERROR] Config file not found: {path}")
        sys.exit(1)
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


SCOPE: dict = _load_yaml("scope.yaml")
SETTINGS: dict = _load_yaml("settings.yaml")

# ---------------------------------------------------------------------------
# Organisation helpers
# ---------------------------------------------------------------------------
# Each org entry: {id, name, brand_color, domains, ip_ranges}
# Supports both the new "organizations:" format and the legacy "domains:" format.

def _parse_organizations(scope: dict) -> list[dict]:
    """Return normalised list of organisation dicts from scope.yaml."""
    if "organizations" in scope:
        orgs = []
        for o in scope["organizations"]:
            orgs.append({
                "id":          o.get("id", "default"),
                "name":        o.get("name", o.get("id", "default")),
                "brand_color": o.get("brand_color", "#003B5C"),
                "domains":     o.get("domains") or [],
                "ip_ranges":   o.get("ip_ranges") or [],
            })
        return orgs
    # Legacy flat format: domains / ip_ranges at root level
    return [{
        "id":          "default",
        "name":        "Default",
        "brand_color": "#003B5C",
        "domains":     scope.get("domains") or [],
        "ip_ranges":   scope.get("ip_ranges") or [],
    }]

ORGANIZATIONS: list[dict] = _parse_organizations(SCOPE)

# Convenience flat lists (used by collectors that don't need org context)
ALL_DOMAINS: list[str] = [d for org in ORGANIZATIONS for d in org["domains"]]
ALL_IP_RANGES: list[str] = [r for org in ORGANIZATIONS for r in org["ip_ranges"]]

# Lookup: domain → org id/name/color  (populated once at startup)
DOMAIN_TO_ORG: dict[str, dict] = {
    domain: org
    for org in ORGANIZATIONS
    for domain in org["domains"]
}

# ---------------------------------------------------------------------------
# Sekoia intake
# ---------------------------------------------------------------------------
SEKOIA_INTAKE_KEY: str = _optional("SEKOIA_INTAKE_KEY")
SEKOIA_INTAKE_URL: str = _optional(
    "SEKOIA_INTAKE_URL", SETTINGS.get("sekoia", {}).get("url", "https://intake.sekoia.io/plain")
)

# ---------------------------------------------------------------------------
# IP enrichment — ipinfo.io (optional token, free up to 50k req/month)
# ---------------------------------------------------------------------------
IPINFO_TOKEN: str = _optional("IPINFO_TOKEN")

# ---------------------------------------------------------------------------
# Azure / Entra ID (optional)
# ---------------------------------------------------------------------------
AZURE_TENANT_ID: str = _optional("AZURE_TENANT_ID").strip()
AZURE_CLIENT_ID: str = _optional("AZURE_CLIENT_ID").strip()
AZURE_CLIENT_SECRET: str = _optional("AZURE_CLIENT_SECRET").strip()
AZURE_ENABLED: bool = bool(AZURE_TENANT_ID and AZURE_CLIENT_ID and AZURE_CLIENT_SECRET)

# ---------------------------------------------------------------------------
# Behaviour
# ---------------------------------------------------------------------------
DRY_RUN: bool = os.getenv("DRY_RUN", "false").strip().lower() == "true"
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
CONFIG_DIR: Path = _CONFIG_DIR
DATA_DIR: Path = _DATA_DIR
DB_PATH: Path = _DATA_DIR / "surface_watch.db"

# Ensure data dir exists
DATA_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
import logging  # noqa: E402

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
