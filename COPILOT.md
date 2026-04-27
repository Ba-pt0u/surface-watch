# surface-watch — AI / Developer notes

## Project overview
Continuous attack surface monitoring tool. Collects from DNS, Certificate Transparency, Azure/Entra ID, RDAP, and lightweight port scanning. Produces CEF alerts to Sekoia.io, interactive relationship cartography (pyvis), and JSON/GraphML exports.

## Tech stack
- **Language**: Python 3.11+
- **Key deps**: dnspython, certstream, azure-identity/mgmt-*, msal, python-nmap, networkx, pyvis, flask, apscheduler, pydantic
- **Deployment**: Docker Compose on Ubuntu, `cap_add: NET_RAW` for nmap
- **Database**: SQLite (in `data/surface_watch.db`)

## Architecture
```
__main__.py → launches scheduler (APScheduler) + certstream listener + Flask web
collectors/  → each collector implements BaseCollector.collect()
graph.py     → AssetGraph wraps NetworkX + SQLite persistence + diff detection
alerting/    → Sekoia HTTP intake (CEF) + local syslog fallback
export/      → pyvis HTML, JSON node-link, GraphML
web/         → Flask dashboard: stats, alerts, cartography, API endpoints
```

## Configuration
- `config/scope.yaml` — root domains, CIDR ranges, exclusions
- `config/settings.yaml` — collector frequencies, ports, alert thresholds
- `.env` — secrets (SEKOIA_INTAKE_KEY, AZURE_* credentials)

## Conventions
- All collectors inherit `BaseCollector` and implement `collect() -> CollectorResult`
- Graph diff produces alerts: NEW (sev 5-7), CHANGED (3-4), REMOVED (1-2)
- CEF format: `CEF:0|SurfaceWatch|ASM|1.0|{id}|{name}|{severity}|{extensions}`
- Colours follow Saur brand: Domain=#003B5C, Subdomain=#00B2A9, IP=#FFCD00, Cert=#9595D2
- No auth on web dashboard v1 (internal network only)

## Key commands
```bash
# Dev
pip install -e ".[dev]"
python -m surface_watch                        # run all
python -m surface_watch --dry-run              # no alerts sent
python -m surface_watch --collector dns        # single collector
pytest tests/

# Docker
docker compose build
docker compose up -d
docker compose logs -f surface-watch
```

## Known pitfalls
- crt.sh rate limit: max 1 req/s, retry with backoff
- nmap requires CAP_NET_RAW or root — handled by Docker cap_add
- certstream WebSocket can disconnect — auto-reconnect built in
- RDAP bootstrap servers have varying rate limits — use Semaphore
- iptoasn.com public API discontinued 2020-12-31 — using ipinfo.io instead (local DB via pyasn is the long-term alternative)
- vis.js CDN blocked by corporate TLS proxy — use `cdn_resources="in_line"` in pyvis
- pyvis `write_html()` crashes on Windows (cp1252) — use `generate_html()` + `write_text(encoding="utf-8")`

## AI assistant instructions
- **Réponses brèves.** Privilégier les tableaux et listes. Éviter les conclusions redondantes.
- **Faisabilité d'abord.** Avant toute implémentation non triviale, vérifier la compatibilité avec le stack existant (Python 3.11, SQLite, pyvis, Flask) et poser les questions nécessaires.
- **Toujours mettre à jour la documentation** après chaque changement fonctionnel :
  - `README.md` — usage visible par l'utilisateur final (sources, config, commandes)
  - `PROJECT.md` — backlog, statut des features, bugs connus, métriques
  - `COPILOT.md` (cette section "Known pitfalls") — tout nouveau piège ou décision technique
- **Commiter** les fichiers de doc dans le même commit que le code (`git add -A`).
- **Tester** après chaque modification : `pytest tests/ -q` doit rester à 22/22.
