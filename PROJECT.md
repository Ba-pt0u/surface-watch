# surface-watch — Project Management

> Document unique de référence : backlog, décisions d'architecture, évolutions prévues, et documentation technique complète pour tout assistant IA ou développeur reprenant le projet.
>
> **Mis à jour :** 2026-04-27  
> **Statut global :** v1.0 implémentée et validée sur saur.fr

---

## Table des matières

1. [Contexte et objectifs](#1-contexte-et-objectifs)
2. [Statut actuel (v1.0)](#2-statut-actuel-v10)
3. [Backlog fonctionnel](#3-backlog-fonctionnel)
4. [Décisions d'architecture (ADR)](#4-décisions-darchitecture-adr)
5. [Documentation technique complète](#5-documentation-technique-complète)
6. [Guide pour assistant IA](#6-guide-pour-assistant-ia)

---

## 1. Contexte et objectifs

**Qui :** Équipe cybersécurité interne.  
**Quoi :** Outil de monitoring continu de la surface d'attaque externe, auto-hébergé sur Ubuntu.  
**Pourquoi :** Détecter en continu les nouveaux assets exposés (sous-domaines, IPs, ports, certificats, ressources cloud) et alerter le SIEM (Sekoia.io) de tout changement.

### Objectifs non négociables
- Fonctionne sur un serveur Ubuntu standard (Docker Compose).
- Sources de données gratuites uniquement + Azure/Entra ID (déjà abonné).
- Alertes CEF vers **Sekoia.io** via HTTP intake.
- Cartographie relationnelle exportable (HTML interactif + JSON + GraphML).
- Aucun secret hardcodé — tout passe par `.env`.

### Périmètre v1
- DNS (A/AAAA/CNAME/MX/NS/TXT/SOA + brute-force subdomains)
- Certificate Transparency : crt.sh (batch) + certstream (temps réel)
- Azure/Entra ID : public IPs, DNS zones, App Services, App Registrations
- RDAP/WHOIS : domaines racines
- Port scan léger : nmap top 100 TCP + TLS cert grab
- IP enrichment : ASN + pays via ipinfo.io

---

## 2. Statut actuel (v1.0)

### Livré et testé

| Composant | Fichier(s) | Statut |
|---|---|---|
| Configuration centralisée | `config.py`, `config/scope.yaml`, `config/settings.yaml` | ✅ OK |
| Modèles Pydantic | `models.py` | ✅ 7 tests |
| Asset Graph (NetworkX + SQLite) | `graph.py` | ✅ 9 tests |
| Collecteur DNS | `collectors/dns.py` | ✅ Testé live (saur.fr, 7 cycles) |
| Collecteur CT batch (crt.sh) | `collectors/ct.py` | ⚠️ Proxy TLS corporate — `verify=False` en contournement |
| Collecteur CT stream (certstream) | `collectors/ct.py` | ✅ Implémenté (non testé réseau interne) |
| Collecteur Azure/Entra ID | `collectors/azure.py` | ✅ Implémenté (non testé sans creds) |
| Collecteur RDAP/WHOIS | `collectors/rdap.py` | ✅ Implémenté (0 enrichissements sur saur.fr) |
| Collecteur port scanner (nmap) | `collectors/portscan.py` | ✅ Implémenté (nmap requis — prod Docker uniquement) |
| IP enrichment (ipinfo.io) | `collectors/rdap.py::IPEnrichCollector` | ✅ Implémenté (IPs privées non enrichies) |
| Alerting CEF → Sekoia HTTP | `alerting/sekoia.py` | ✅ 6 tests — fallback fichier local OK |
| Export HTML pyvis | `export/pyvis_map.py` | ✅ Testé live (~720 KB, vis.js embarqué, layout arborescent) |
| Export JSON node-link | `export/formats.py` | ✅ Testé live |
| Export GraphML | `export/formats.py` | ✅ Testé live |
| Dashboard Flask | `web/app.py`, `web/templates/` | ✅ Refonte UI 2026-04-27 — alertes CEF parsées |
| Orchestrateur principal | `__main__.py` | ✅ Testé live sur saur.fr |
| Docker Compose | `Dockerfile`, `docker-compose.yml` | ✅ Implémenté |
| Tests unitaires | `tests/` | ✅ 22/22 passent |

### Métriques scan live (saur.fr, 2026-04-27 — cycle #7)
- Durée collecte DNS : ~0.9s (brute-force 107 mots)
- Assets en base : 58 (1 domaine, 14 sous-domaines, 17 IPs, 28 DNS records, 2 cibles CNAME externes)
- Edges : 59
- Nœuds visibles sur la carte : 30 (DNS records masqués pour lisibilité)
- Alertes CEF générées : 26 (dont 1 NEW sévérité 5 : nouvelle IP 37.58.168.176 sur mobile.saur.fr)
- Tous les exports produits sans erreur

### Bugs connus / Limitations v1

| ID | Description | Sévérité | Contournement |
|---|---|---|---|
| BUG-001 | GraphML export échoue si un attribut est `None` | Corrigé v1.0 | — |
| BUG-002 | CNAME targets créés sans arête → nœuds orphelins dans le graphe | Corrigé v1.0 | `dns.py` ajoute `RESOLVES_TO` + `HAS_SUBDOMAIN` depuis la cible CNAME |
| BUG-003 | `pyvis.write_html()` utilise le locale système (cp1252 Windows) → crash Unicode | Corrigé v1.0 | `generate_html()` + `write_text(encoding="utf-8")` |
| BUG-004 | CSS `body > div:not(#mynetwork)` masquait le wrapper `.card` de pyvis → graphe invisible | Corrigé v1.0 | Règle `body > .card { height: 100vh }` explicite |
| LIM-001 | Scan actif limité à 256 hosts max par CIDR (anti-DoS volontaire) | Info | Modifier `portscan.py:45` |
| LIM-002 | Dashboard Flask sans authentification | Info | Réseau interne uniquement |
| LIM-003 | IPEnrichCollector appelé séquentiellement (lent pour >100 IPs) | Faible | Futur : `ThreadPoolExecutor` |
| LIM-004 | certstream dépend d'un service tiers (calidog.io) | Info | Futur : CT log direct |
| LIM-005 | RDAP collector enrichit seulement les domaines racines (pas les sous-domaines) | Faible | Futur : étendre scope |
| LIM-006 | CT batch (crt.sh) bloqué par proxy TLS corporate en dev | Info | Prod Docker sans proxy : fonctionne |
| LIM-007 | nmap absent sur Windows dev → portscan sauté silencieusement | Info | Prod Docker : `cap_add: NET_RAW` |

---

## 3. Backlog fonctionnel

### Notation priorité : 🔴 Haute · 🟡 Moyenne · 🟢 Basse

---

### FEAT-001 — Authentification dashboard web 🔴

**Problème :** Le dashboard Flask n'a aucune authentification (acceptable réseau interne, risqué en exposition).  
**Solution proposée :** HTTP Basic Auth avec mot de passe hashé (bcrypt) stocké dans `.env`, ou intégration Entra ID OIDC si déjà utilisé.  
**Fichiers à modifier :** `web/app.py` — décorateur `@require_auth` sur toutes les routes, ou Flask-Login.  
**Complexité :** Faible (Basic Auth) · Moyenne (OIDC)

---

### FEAT-002 — Notifications Webhook (Teams / Slack / Email) 🔴

**Problème :** Seule Sekoia.io reçoit les alertes. L'équipe veut une notif immédiate sur certains événements critiques sans accéder au SIEM.  
**Solution proposée :**
- Nouveau module `alerting/webhook.py` avec interface commune.
- Config dans `settings.yaml` :
  ```yaml
  notifications:
    teams_webhook: "https://outlook.office.com/webhook/..."
    slack_webhook: "https://hooks.slack.com/services/..."
    email_smtp: "smtp.example.com:587"
    # Filtrer par sévérité minimale
    min_severity: 7
  ```
- Déclenché uniquement pour `severity >= min_severity` pour éviter le flood.  
**Fichiers à créer :** `alerting/webhook.py`  
**Fichiers à modifier :** `alerting/sekoia.py::process_diffs` pour appeler les webhooks en parallèle  
**Complexité :** Moyenne

---

### FEAT-003 — Collecteur Shodan (API gratuite limitée) 🟡

**Problème :** Shodan fournit des données de scan internet sans qu'on ait à scanner activement.  
**Solution proposée :**
- `collectors/shodan.py` : `ShodanCollector`
- Requête `https://api.shodan.io/dns/domain/{domain}?key={key}` pour sous-domaines
- Requête `https://api.shodan.io/shodan/host/{ip}?key={key}` pour ports/services
- Clé API dans `.env` : `SHODAN_API_KEY` (optionnel — collector skippé si absent)
- Intégration dans le scheduler : fréquence `P1D` (1/jour, limite API gratuite)  
**Fichiers à créer :** `collectors/shodan.py`  
**Fichiers à modifier :** `__main__.py::_register_collectors`  
**Complexité :** Faible

---

### FEAT-004 — Collecteur Censys (v2 API) 🟡

**Problème :** Complémente Shodan pour la découverte de certificats et hosts.  
**Solution proposée :**
- `collectors/censys.py` : requêtes sur `search.censys.io/api/v2/`
- Recherche par `parsed.names: example.com` dans l'index certificats
- Auth : `CENSYS_API_ID` + `CENSYS_API_SECRET` dans `.env` (free tier : 250 req/mois)  
**Fichiers à créer :** `collectors/censys.py`  
**Complexité :** Faible

---

### FEAT-005 — Historique des snapshots et vue temporelle 🟡

**Problème :** Actuellement on ne garde que le dernier état dans SQLite. Impossible de voir l'évolution dans le temps.  
**Solution proposée :**
- Table SQLite `asset_history(uid, asset_type, snapshot_date, data)` : snapshot complet à chaque cycle.
- API endpoint `GET /api/asset/{uid}/history` → timeline JSON.
- Vue dashboard : graphique sparkline du nombre d'assets par type dans le temps.  
**Fichiers à modifier :** `graph.py::save()` (ajouter écriture history), `web/app.py` (nouveau endpoint), `web/templates/dashboard.html` (chart.js ou simple table)  
**Complexité :** Moyenne

---

### FEAT-006 — Détection d'assets "dangling" (CNAME orphelins) 🟡

**Problème :** Un CNAME qui pointe vers un service cloud supprimé (ex: Azure App Service décommissionné) peut être pris en charge par un attaquant (subdomain takeover).  
**Solution proposée :**
- Post-processing après le collecteur DNS : pour chaque CNAME, vérifier si la cible existe et est contrôlée.
- Liste de patterns vulnérables (Azure, AWS, GCP, Fastly, Heroku...) à maintenir dans `config/takeover_signatures.yaml`.
- Alert `DANGLING_CNAME` avec severity 9.  
**Fichiers à créer :** `collectors/dangling.py`, `config/takeover_signatures.yaml`  
**Complexité :** Moyenne

---

### FEAT-007 — Scan SSL/TLS avancé (cipher suites, HSTS, expiry) 🟡

**Problème :** Le TLS cert grab actuel récupère juste le certificat. On ne vérifie pas les cipher suites faibles, l'absence de HSTS, ou les certificats expirant bientôt.  
**Solution proposée :**
- Enrichissement du `PortScanCollector` ou nouveau `collectors/tlsscan.py`
- Utiliser `ssl.SSLContext.get_ciphers()` + connexion directe
- Alertes : `CERT_EXPIRING_SOON` (< 30 jours), `WEAK_CIPHER`, `HSTS_MISSING`
- Config dans `settings.yaml` : `tls_expiry_warning_days: 30`  
**Fichiers à créer/modifier :** `collectors/portscan.py` ou nouveau `collectors/tlsscan.py`  
**Complexité :** Moyenne

---

### FEAT-008 — Multi-tenant / multi-organisation ✅ Implémentée (v1.1)

**Problème :** Pour l'instant un seul scope (`config/scope.yaml`). Si on surveille plusieurs entités (Saur, Cise TP, Stereau...), il faut tout mélanger ou dupliquer les déploiements.  
**Implémentation :**
- `config/scope.yaml` : structure `organizations: [{id, name, brand_color, domains, ip_ranges}]` — rétrocompatible avec l'ancien format plat
- `config.py` : helpers `ORGANIZATIONS`, `ALL_DOMAINS`, `ALL_IP_RANGES`, `DOMAIN_TO_ORG`
- `models.py` : champ `organization: str = ""` sur `Asset` (base class)
- `graph.py` : auto-assignation + propagation de l'org via `DOMAIN_TO_ORG` ; `stats()` retourne `by_organization`
- `collectors/dns.py` : paramètre `org_id` propagé à tous les assets créés
- `alerting/sekoia.py` : extension CEF `cs4=<org_id> cs4Label=organization`
- `export/pyvis_map.py` : bordure de nœud colorée par org, légende dynamique multi-org
- `web/app.py` : filtre `?org=` dans `/api/alerts` et route `/` ; parsing `cs4` dans les alertes
- `web/templates/dashboard.html` : onglets de filtrage org (affiché si >1 org configurée)
- `web/static/style.css` : `.org-tabs` / `.org-tab` / `.org-tab-active` avec `--org-color`

---

### FEAT-009 — Persistance PostgreSQL (alternative à SQLite) 🟢

**Problème :** SQLite tient bien jusqu'à ~100k assets. Au-delà, ou si on veut plusieurs workers, PostgreSQL est préférable.  
**Solution proposée :**
- Variable `DATABASE_URL` dans `.env` : si présente et commence par `postgresql://`, utiliser psycopg2 ; sinon SQLite.
- Abstraction via une couche fine dans `graph.py` (les requêtes SQL sont déjà centralisées).
- `docker-compose.yml` : service PostgreSQL optionnel avec `profiles: [postgres]`.  
**Fichiers à modifier :** `graph.py`, `docker-compose.yml`, `.env.example`  
**Complexité :** Moyenne

---

### FEAT-010 — API REST complète (lecture seule) 🟢

**Problème :** Le dashboard web est utile mais les équipes veulent requêter les données programmatiquement (intégration CI/CD, scripts d'inventaire).  
**Solution proposée :**
- Endpoints supplémentaires sur le Flask :
  - `GET /api/assets?type=subdomain&limit=100&offset=0` — liste paginée
  - `GET /api/asset/{uid}` — détail d'un asset
  - `GET /api/assets/search?q=example.com` — recherche textuelle
  - `GET /api/graph/neighbors/{uid}` — assets voisins dans le graph
- Réponses JSON avec `Content-Type: application/json`
- Clé API simple dans header `X-API-Key` depuis `.env`  
**Fichiers à modifier :** `web/app.py`  
**Complexité :** Faible

---

### FEAT-011 — Intégration CT logs directs (sans certstream tiers) 🟢

**Problème :** certstream dépend du service tiers `certstream.calidog.io`. Si ce service est indisponible, le monitoring temps réel tombe.  
**Solution proposée :**
- Interroger directement les CT logs (Google Argon, Cloudflare Nimbus) via l'API Trillian/RFC 6962.
- Ou utiliser `crt.sh` en polling fréquent (toutes les 5 min) comme alternative.
- Garder certstream comme source principale mais ajouter crt.sh polling comme fallback.  
**Fichiers à modifier :** `collectors/ct.py`  
**Complexité :** Élevée

---

### FEAT-012 — Export STIX 2.1 🟢

**Problème :** Les équipes threat intel veulent partager les assets découverts en format standard STIX 2.1 (compatible avec MISP, OpenCTI).  
**Solution proposée :**
- `export/stix.py` : convertir les assets en observables STIX 2.1 (`domain-name`, `ipv4-addr`, `x509-certificate`, `network-traffic`)
- Utiliser la lib `stix2` (PyPI)
- Endpoint Flask `GET /api/stix.json`  
**Fichiers à créer :** `export/stix.py`  
**Fichiers à modifier :** `web/app.py`  
**Complexité :** Moyenne

---

## 4. Décisions d'architecture (ADR)

### ADR-001 — Python pur, pas de frontend JS séparé
**Date :** 2026-04-27 · **Statut :** Accepté

**Contexte :** Choix entre (A) Python + HTML/Jinja2 statique, (B) FastAPI + React SPA (style dynamix-carto), (C) Flask + templates.

**Décision :** Option (C) Flask + Jinja2.

**Justification :**
- Cohérent avec les autres projets Python du workspace.
- Zéro build step (pas de `npm build`).
- Un seul process à déployer dans Docker.
- Suffisant pour un usage interne (pas de millions d'utilisateurs).

**Conséquences :** Le dashboard est fonctionnel mais moins riche qu'une SPA. Si besoin d'interactivité avancée (filtres dynamiques, graphiques temps réel), migrer vers FastAPI + React (partir de dynamix-carto comme base).

---

### ADR-002 — NetworkX + SQLite, pas Neo4j
**Date :** 2026-04-27 · **Statut :** Accepté

**Contexte :** Choix du moteur de graphe : (A) NetworkX in-memory + SQLite, (B) Neo4j, (C) PostgreSQL avec table de relations.

**Décision :** Option (A) NetworkX + SQLite.

**Justification :**
- Volume attendu < 100k assets → SQLite largement suffisant.
- Zéro dépendance serveur supplémentaire (pas de JVM, pas de service Neo4j à gérer).
- NetworkX donne accès à tous les algorithmes de graphe (plus courts chemins, composantes connexes, centralité) si besoin.
- Migration vers PostgreSQL ou Neo4j possible sans casser l'interface `AssetGraph` (ADR-009 prévu).

**Conséquences :** Le graph est chargé entièrement en RAM à chaque démarrage. Pour > 500k nœuds, revoir.

---

### ADR-003 — nmap plutôt que masscan
**Date :** 2026-04-27 · **Statut :** Accepté

**Contexte :** Choix du scanner de ports actif : (A) nmap, (B) masscan, (C) scapy.

**Décision :** Option (A) nmap via `python-nmap`.

**Justification :**
- Détection de service (`-sV`) incluse nativement.
- Binding Python mature (`python-nmap`).
- top 100 ports = scan rapide (< 30s/hôte).
- masscan est plus rapide pour les larges ranges mais n'a pas de détection de service et son binding Python est peu maintenu.

**Conséquences :** Nmap nécessite `CAP_NET_RAW` ou root → géré par `cap_add: NET_RAW` dans Docker. Pour scanner > 10k hôtes, envisager masscan + nmap en deux passes (FEAT non prévu).

---

### ADR-004 — certstream (calidog.io) pour le CT temps réel
**Date :** 2026-04-27 · **Statut :** Accepté (révision prévue FEAT-011)

**Contexte :** Comment monitorer les Certificate Transparency logs en temps réel sans infra dédiée.

**Décision :** Utiliser le service `wss://certstream.calidog.io/` via la lib `certstream`.

**Justification :**
- Zéro infrastructure à gérer.
- Couvre l'ensemble des CT logs majeurs.
- Reconnexion automatique implémentée.

**Risque :** Dépendance à un service tiers. Si `calidog.io` est indisponible, le monitoring CT temps réel tombe silencieusement (le batch crt.sh reste actif).

**Mitigation :** FEAT-011 prévoit un fallback CT direct.

---

### ADR-005 — Format d'alerte CEF vers Sekoia.io
**Date :** 2026-04-27 · **Statut :** Accepté

**Contexte :** Format des alertes envoyées au SIEM : (A) CEF, (B) JSON structuré, (C) RFC 5424 syslog.

**Décision :** CEF (ArcSight Common Event Format) via HTTP intake Sekoia.

**Justification :**
- CEF est le standard reconnu par Sekoia.io et compatible avec les parsers intake existants dans le workspace (`automation-library/`).
- HTTP intake Sekoia (`/plain`) accepte CEF ligne par ligne.
- Pas besoin d'un concentrateur syslog intermédiaire.

**Format :**
```
CEF:0|SurfaceWatch|ASM|1.0|{SignatureID}|{Name}|{Severity}|{Extensions}
```
Extensions utilisées : `dhost` (FQDN), `src` (IP), `cs1/cs1Label` (assetType), `cs2/cs2Label` (changeType), `msg` (détail JSON tronqué à 1024 chars), `rt` (timestamp).

---

### ADR-006 — Pas d'authentification sur le dashboard v1
**Date :** 2026-04-27 · **Statut :** Accepté avec dette technique (FEAT-001)

**Contexte :** Le dashboard Flask expose des informations sensibles (IPs, sous-domaines, ports ouverts).

**Décision :** Pas d'auth en v1. Contrainte : **exposition réseau interne uniquement** (bind sur interface interne ou derrière un reverse proxy interne).

**Conditions de révision :** Dès que le dashboard est accessible depuis l'extérieur ou qu'un reverse proxy public est mis en place → implémenter FEAT-001.

---

### ADR-007 — Couleurs Saur pour la cartographie
**Date :** 2026-04-27 · **Statut :** Accepté

**Contexte :** Choix des couleurs des nœuds dans la cartographie pyvis.

**Décision :** Utiliser la palette de la charte graphique Saur définie dans `AGENTS.md`.

| Type de nœud | Couleur | Token Saur |
|---|---|---|
| Domain | `#003B5C` | Corporate Blue |
| Subdomain | `#00B2A9` | Glacier Turquoise |
| IP Address | `#FFCD00` | Horizon Yellow |
| Certificate | `#9595D2` | Lake Lilac |
| Port/Service | `#E87722` | Orange (hors charte, acceptable) |
| Cloud Resource | `#4CAF50` | Vert (hors charte, acceptable) |

---

### ADR-008 — Un seul processus (pas de worker séparé)
**Date :** 2026-04-27 · **Statut :** Accepté

**Contexte :** Architecture multi-process (scheduler + web + certstream dans des processus séparés) vs mono-process avec threads.

**Décision :** Mono-process, multi-threads : APScheduler en background thread, certstream en background thread, Flask en background thread, main thread attend le signal d'arrêt.

**Justification :** Simplicité de déploiement (un seul container). Les collecteurs ne sont pas CPU-bound (IO-bound : réseau), donc les threads Python (GIL) conviennent.

**Conséquences :** Si un collecteur bloque un thread trop longtemps, il peut retarder les autres. Solution : timeout explicite sur toutes les opérations réseau (déjà implémenté).

---

## 5. Documentation technique complète

### 5.1 Structure des fichiers

```
surface-watch/
├── .env.example                    # Template de variables d'environnement
├── .gitignore
├── config/
│   ├── scope.yaml                  # Périmètre : domaines, IP ranges, exclusions
│   ├── settings.yaml               # Fréquences, seuils, ports, limites
│   └── wordlist.txt                # Wordlist pour brute-force DNS (107 mots)
├── data/                           # Volume Docker (gitignore sauf .gitkeep)
│   ├── surface_watch.db            # SQLite : assets, edges, scan_runs
│   ├── map.html                    # Cartographie pyvis (auto-généré)
│   ├── graph.json                  # Export JSON node-link (auto-généré)
│   ├── graph.graphml               # Export GraphML (auto-généré)
│   └── alerts.log                  # Log local des alertes CEF
├── src/surface_watch/
│   ├── __init__.py
│   ├── __main__.py                 # Entrypoint : orchestrateur principal
│   ├── config.py                   # Config centralisée (env + YAML)
│   ├── graph.py                    # AssetGraph : NetworkX + SQLite + diff
│   ├── models.py                   # Modèles Pydantic : assets, edges, résultats
│   ├── collectors/
│   │   ├── __init__.py
│   │   ├── base.py                 # BaseCollector ABC
│   │   ├── dns.py                  # DNSCollector
│   │   ├── ct.py                   # CTBatchCollector + CTStreamListener
│   │   ├── azure.py                # AzureCollector
│   │   ├── rdap.py                 # RDAPCollector + IPEnrichCollector
│   │   └── portscan.py             # PortScanCollector
│   ├── alerting/
│   │   ├── __init__.py
│   │   └── sekoia.py               # CEF → Sekoia HTTP intake
│   ├── export/
│   │   ├── __init__.py
│   │   ├── pyvis_map.py            # Export HTML interactif
│   │   └── formats.py              # Export JSON + GraphML
│   └── web/
│       ├── __init__.py
│       ├── app.py                  # Flask : routes + API
│       ├── templates/
│       │   ├── base.html
│       │   ├── dashboard.html
│       │   └── map.html
│       └── static/
│           └── style.css
├── tests/
│   ├── test_graph.py               # 9 tests AssetGraph
│   ├── test_models.py              # 7 tests modèles Pydantic
│   └── test_alerting.py            # 6 tests CEF formatting
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
└── README.md
```

---

### 5.2 Modèle de données

#### Types d'assets (`AssetType`)

| Type | UID pattern | Attributs clés |
|---|---|---|
| `domain` | `"example.com"` | `fqdn`, `registrar`, `whois_org`, `created`, `expires`, `nameservers[]` |
| `subdomain` | `"www.example.com"` | `fqdn`, `parent_domain` |
| `ip_address` | `"1.2.3.4"` | `address`, `version` (4/6), `asn`, `asn_org`, `country` |
| `certificate` | `"cert:sha256_prefix"` ou `"cert:serial"` | `sha256`, `serial`, `issuer`, `not_before`, `not_after`, `sans[]` |
| `port_service` | `"1.2.3.4:tcp/443"` | `ip`, `port`, `protocol`, `service`, `product`, `version`, `banner` |
| `cloud_resource` | `"azure:/subscriptions/.../..."` ou `"azure:app:{appId}"` | `provider`, `resource_type`, `resource_id`, `name`, `subscription`, `resource_group` |
| `dns_record` | `"example.com:A:1.2.3.4"` | `fqdn`, `rrtype`, `rdata`, `ttl` |

#### Types de relations (`EdgeType`)

| Relation | Source | Cible |
|---|---|---|
| `has_subdomain` | Domain / Subdomain | Subdomain |
| `resolves_to` | Domain / Subdomain | IPAddress |
| `issued_for` | Certificate | Domain / Subdomain |
| `serves_cert` | IPAddress | Certificate |
| `has_public_ip` | CloudResource | IPAddress |
| `has_hostname` | CloudResource | Domain / Subdomain |
| `belongs_to_asn` | IPAddress | (attribut sur le nœud, pas d'entité ASN) |
| `exposes_port` | IPAddress | PortService |
| `has_dns_record` | Domain / Subdomain | DNSRecord |

#### Schéma SQLite

```sql
-- Assets persistés avec upsert (ON CONFLICT(uid) DO UPDATE)
assets(uid TEXT PK, asset_type TEXT, source TEXT, first_seen TEXT, last_seen TEXT, data TEXT/JSON)

-- Relations
edges(uid TEXT PK, source_uid TEXT FK, target_uid TEXT FK, edge_type TEXT, data TEXT/JSON)

-- Historique des scans
scan_runs(run_id INTEGER PK AUTOINCREMENT, started_at TEXT, finished_at TEXT, collector TEXT, status TEXT, summary TEXT/JSON)
```

---

### 5.3 Flow de données (cycle complet)

```
__main__.py::run_scan_cycle(graph, collectors)
  │
  ├── Phase 1 — Discovery (parallélisable manuellement ou via ThreadPool futur)
  │   ├── DNSCollector.run()        → CollectorResult (assets + edges)
  │   ├── CTBatchCollector.run()    → CollectorResult
  │   ├── AzureCollector.run()      → CollectorResult
  │   └── RDAPCollector.run()       → CollectorResult
  │       → graph.ingest_result() pour chaque
  │
  ├── Phase 2 — Enrichment (dépend de Phase 1 pour les IPs)
  │   ├── PortScanCollector.set_ips(graph.get_all_ips()); .run()
  │   └── IPEnrichCollector.set_ips(graph.get_all_ips()); .run()
  │       → graph.ingest_result() pour chaque
  │
  ├── Diff
  │   └── graph.diff() → list[DiffEntry] (new / changed / removed)
  │
  ├── Alerting
  │   └── sekoia.process_diffs(diffs) → convertit en CEF + POST Sekoia + log local
  │
  ├── Persistance
  │   └── graph.save() → upsert SQLite (assets + edges)
  │
  └── Export
      ├── pyvis_map.generate_map(graph.g) → data/map.html
      ├── formats.export_json(graph.g)    → data/graph.json
      └── formats.export_graphml(graph.g) → data/graph.graphml
```

---

### 5.4 Ajouter un nouveau collecteur

**Procédure standard (copier ce template) :**

```python
# src/surface_watch/collectors/mon_collecteur.py
from surface_watch import config
from surface_watch.collectors.base import BaseCollector
from surface_watch.models import Asset, CollectorResult, Edge, Subdomain, EdgeType

class MonCollecteur(BaseCollector):
    name = "mon_collecteur"  # doit être unique

    def __init__(self) -> None:
        # Lire la config depuis config.SETTINGS
        self._api_key = config._optional("MON_API_KEY")
        if not self._api_key:
            # Collecteur optionnel : logger un warning et skip
            pass

    def collect(self) -> CollectorResult:
        assets: list[Asset] = []
        edges: list[Edge] = []
        errors: list[str] = []

        for domain in config.SCOPE.get("domains", []):
            try:
                # ... appel API ou DNS ...
                sub = Subdomain(uid="new.example.com", fqdn="new.example.com",
                                parent_domain=domain, source=self.name)
                assets.append(sub)
            except Exception as exc:
                errors.append(f"MonCollecteur {domain}: {exc}")

        return CollectorResult(
            collector_name=self.name,
            assets=assets, edges=edges, errors=errors,
        )
```

**Enregistrement dans `__main__.py` :**

```python
# Dans _register_collectors()
from surface_watch.collectors.mon_collecteur import MonCollecteur
_COLLECTOR_CLASSES["mon_collecteur"] = MonCollecteur
```

**Configuration du scheduler dans `config/settings.yaml` :**

```yaml
schedule:
  mon_collecteur: PT12H  # toutes les 12h
```

**Variable d'environnement dans `.env.example` :**

```
MON_API_KEY=  # Optionnel : clé API pour MonCollecteur
```

---

### 5.5 Ajouter un type d'alerte

1. Ajouter dans `config/settings.yaml` sous `alerting.severity` :
   ```yaml
   alerting:
     severity:
       mon_evenement: 7
   ```

2. Dans `alerting/sekoia.py::diff_to_cef()`, ajouter un cas dans le bloc conditionnel :
   ```python
   elif diff.asset_type == "mon_type" and diff.category == "new":
       event_id = "MON_EVENEMENT"
       event_name = "Description lisible"
       severity = settings.get("mon_evenement", 5)
   ```

3. Ajouter un test dans `tests/test_alerting.py`.

---

### 5.6 Variables d'environnement

| Variable | Obligatoire | Défaut | Description |
|---|---|---|---|
| `SEKOIA_INTAKE_KEY` | Non* | — | Clé HTTP intake Sekoia. Sans elle, alertes seulement en local. |
| `SEKOIA_INTAKE_URL` | Non | `https://intake.sekoia.io/plain` | URL du endpoint intake |
| `AZURE_TENANT_ID` | Non | — | Tenant Azure. Sans les 3 AZURE_*, le collecteur Azure est skippé. |
| `AZURE_CLIENT_ID` | Non | — | App registration client ID |
| `AZURE_CLIENT_SECRET` | Non | — | App registration secret |
| `DRY_RUN` | Non | `false` | Si `true`, aucune alerte envoyée à Sekoia |
| `LOG_LEVEL` | Non | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `SW_CONFIG_DIR` | Non | `./config` | Chemin du dossier de configuration |
| `SW_DATA_DIR` | Non | `./data` | Chemin du dossier de données persistantes |

---

### 5.7 Permissions Azure requises (pour AzureCollector)

L'App Registration Azure doit avoir les rôles/permissions suivants :

| API / Scope | Permission | Raison |
|---|---|---|
| Azure Resource Manager | `Reader` (rôle RBAC) sur chaque subscription | Lister les ressources, IPs publiques, App Services |
| Azure DNS | `DNS Zone Reader` ou `Reader` | Lire les zones DNS et record sets |
| Microsoft Graph | `Domain.Read.All` | Domaines vérifiés Entra ID |
| Microsoft Graph | `Application.Read.All` | App registrations et redirect URIs |

Commandes PowerShell pour créer l'App Registration :
```powershell
# Créer l'app
$app = New-AzADApplication -DisplayName "surface-watch"
$sp = New-AzADServicePrincipal -ApplicationId $app.AppId

# Attribuer Reader sur la subscription
New-AzRoleAssignment -ObjectId $sp.Id -RoleDefinitionName "Reader" -Scope "/subscriptions/{sub-id}"

# Les permissions Graph doivent être accordées via le portail Azure (Admin consent requis)
```

---

### 5.8 Configuration scope.yaml — schéma complet

```yaml
# Domaines racines à surveiller
# Les sous-domaines sont découverts automatiquement via DNS, CT, Azure
domains:
  - example.com
  - other-domain.fr

# Ranges IP à inclure dans le scan de ports
# Format CIDR. Limité à /24 max par plage (256 hosts max) pour éviter les scans massifs
ip_ranges:
  - 198.51.100.0/24   # IPv4
  # - 2001:db8::/48   # IPv6 supporté

# Exclusions — assets ignorés même s'ils sont découverts
exclusions:
  domains:
    - internal.example.com   # domaine interne, pas d'intérêt externe
  ip_ranges:
    - 10.0.0.0/8             # RFC 1918 — toujours exclure les privées
    - 172.16.0.0/12
    - 192.168.0.0/16
```

---

### 5.9 Schéma CEF — champs utilisés

```
CEF:0|SurfaceWatch|ASM|1.0|{SignatureID}|{Name}|{Severity}|{Extensions}
```

| Champ | Valeurs | Description |
|---|---|---|
| `SignatureID` | `NEW_SUBDOMAIN`, `NEW_IP`, `NEW_CERT`, `NEW_PORT`, `CRITICAL_PORT`, `NEW_CLOUD`, `NEW_ASSET`, `ASSET_CHANGED`, `ASSET_REMOVED`, `TYPOSQUAT_CERT` (certstream) | Identifiant unique de l'événement |
| `Severity` | 1–10 | Défini dans `settings.yaml::alerting.severity` |
| `dhost` | FQDN ou UID de l'asset | Asset concerné |
| `src` | Adresse IP si disponible | IP source de l'asset |
| `cs1` / `cs1Label` | type d'asset / `"assetType"` | Ex: `subdomain`, `ip_address` |
| `cs2` / `cs2Label` | `new`/`changed`/`removed` / `"changeType"` | Catégorie de changement |
| `msg` | JSON tronqué à 1024 chars | Détails de l'asset ou des changements |
| `rt` | `"Apr 27 2026 11:40:00"` | Timestamp RFC 5424 |

---

### 5.10 Routes du dashboard web

| Method | Route | Description |
|---|---|---|
| GET | `/` | Dashboard principal : stats, scans récents, alertes récentes |
| GET | `/map` | Page cartographie (iframe pyvis ou message "pas encore de carte") |
| GET | `/map/raw` | Fichier `map.html` pyvis brut (servi par Flask) |
| GET | `/api/stats` | JSON : compteurs par type d'asset + derniers scans |
| GET | `/api/alerts?limit=N` | JSON : dernières N alertes depuis `alerts.log` |
| GET | `/api/graph.json` | Download JSON node-link (NetworkX format) |
| GET | `/api/graph.graphml` | Download GraphML |

---

## 6. Guide pour assistant IA

> Section destinée aux assistants IA (GitHub Copilot, Claude, GPT…) qui reprennent le projet.

### Ce que tu dois savoir avant de toucher au code

1. **Lis `COPILOT.md`** pour les conventions de code et les commandes clés.
2. **Le projet est Python 3.11+**, Pydantic v2, Flask 3.x, NetworkX 3.x.
3. **Tous les collecteurs héritent de `BaseCollector`** et retournent un `CollectorResult`. Ne jamais appeler `collect()` directement — toujours passer par `run()` qui gère le logging et le catch d'exceptions.
4. **Le graph est chargé en RAM** (`AssetGraph.load()`) au démarrage et flushed (`save()`) après chaque cycle. Ne pas écrire dans SQLite directement.
5. **`config.DRY_RUN`** doit toujours être vérifié avant tout POST vers Sekoia ou tout write vers l'extérieur.
6. **Les tests se trouvent dans `tests/`** — les faire passer avant tout commit : `pytest tests/ -q`.
7. **Les couleurs des nœuds pyvis** suivent la charte Saur (définie dans `AGENTS.md` et `ADR-007`). Ne pas les changer sans raison.

### Patterns à réutiliser systématiquement

| Besoin | Où le trouver |
|---|---|
| Appel API avec retry/backoff | `alerting/sekoia.py::send_to_sekoia()` — copier la boucle retry |
| Variable d'env obligatoire | `config.py::_require()` |
| Variable d'env optionnelle | `config.py::_optional()` |
| Rate limiting simple | `collectors/ct.py` — `time.sleep(1.0 / self._rate_limit)` |
| Pagination `@odata.nextLink` (Graph API) | `collectors/azure.py::_collect_entra_id()` |
| Lecture config YAML | `config.SETTINGS.get("section", {}).get("key", default)` |

### Pièges à éviter

- **Ne jamais mettre de secrets dans le code** — toujours `config._optional("MA_CLE")` + `.env`.
- **Ne pas modifier `graph.g` (NetworkX) directement** depuis un collecteur — toujours passer par `graph.ingest_asset()` / `graph.ingest_edge()`.
- **`GraphML` ne supporte pas `None`** — toujours convertir en `""` avant export (voir `export/formats.py::export_graphml()`).
- **Le scheduler APScheduler** est configuré avec `max_instances=1` et `coalesce=True` pour éviter les runs parallèles du même collecteur.
- **Flask `app.run(use_reloader=False)`** est obligatoire quand Flask tourne dans un thread non-principal (le reloader fork le process, ce qui cause des bugs avec APScheduler).
- **nmap** peut lever `nmap.PortScannerError` si nmap n'est pas installé — toujours wrapper dans `try/except` avec message d'erreur clair.

### Ajouter une dépendance

1. Ajouter dans `pyproject.toml::project.dependencies`
2. Reconstruire : `pip install -e ".[dev]"` (dev) ou `docker compose build` (prod)
3. Mettre à jour `Dockerfile` si la dépendance nécessite un paquet système (`apt`)

### Commandes de référence rapide

```bash
# Tests
pytest tests/ -v
pytest tests/test_graph.py::test_diff_new_assets -v  # test unitaire

# Dry-run d'un collecteur
python -m surface_watch --dry-run --collector dns
python -m surface_watch --dry-run --collector ct_batch
python -m surface_watch --dry-run --collector azure

# Scan complet dry-run
python -m surface_watch --dry-run --scan-now --no-web --no-certstream

# Démarrage complet (dev)
python -m surface_watch --scan-now

# Docker
docker compose build
docker compose up -d
docker compose logs -f surface-watch
docker compose exec surface-watch python -m surface_watch --dry-run --collector dns
```
