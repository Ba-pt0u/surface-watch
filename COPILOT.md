# surface-watch — AI / Developer notes

## Project overview
Continuous attack surface monitoring tool. Collects from DNS, Certificate Transparency, Azure/Entra ID, RDAP, and lightweight port scanning. Produces CEF alerts to Sekoia.io, interactive relationship cartography (Cytoscape.js — 3 layouts, live via Flask), and JSON/GraphML exports.

## Tech stack
- **Language**: Python 3.11+
- **Key deps**: dnspython, certstream, azure-identity/mgmt-*, msal, python-nmap, networkx, flask, apscheduler, pydantic
- **Cartography JS**: cytoscape.js v3.30.2 + dagre.js v0.8.5 + cytoscape-dagre v2.5.0 (bundled locally in `web/static/js/` — offline-capable, no CDN)
- **Deployment**: Docker Compose on Ubuntu, `cap_add: NET_RAW` for nmap
- **Database**: SQLite (in `data/surface_watch.db`)

## Architecture
```
__main__.py → launches scheduler (APScheduler) + certstream listener + Flask web
collectors/  → each collector implements BaseCollector.collect()
graph.py     → AssetGraph wraps NetworkX + SQLite persistence + diff detection
alerting/    → Sekoia HTTP intake (CEF) + local syslog fallback
export/      → JSON node-link (data/graph.json), GraphML (data/graph.graphml)
web/         → Flask dashboard: stats, asset browser, scan history, live cartography (Cytoscape.js)
web/static/js/ → cytoscape.min.js, dagre.min.js, cytoscape-dagre.min.js (local, offline-capable)
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
- pyvis removed (2026-04-28): map is now served live by Flask via `/api/graph.json` → Cytoscape.js. `export/pyvis_map.py` is kept but not called.

## AI assistant instructions
## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---

- **Toujours mettre à jour la documentation** après chaque changement fonctionnel :
  - `README.md` — usage visible par l'utilisateur final (sources, config, commandes)
  - `PROJECT.md` — backlog, statut des features, bugs connus, métriques
  - `COPILOT.md` (cette section "Known pitfalls") — tout nouveau piège ou décision technique
- **Commiter** les fichiers de doc dans le même commit que le code (`git add -A`).
- **Tester** après chaque modification : `pytest tests/ -q` doit rester à 22/22.
