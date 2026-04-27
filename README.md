# Surface Watch — Continuous Attack Surface Monitor

Outil de monitoring continu de la surface d'attaque externe. Collecte et correle les donnees depuis de multiples sources (DNS, Certificate Transparency, Azure/Entra ID, RDAP, scan de ports) pour produire une cartographie relationnelle et des alertes vers Sekoia.io.

## Quick Start

### 1. Configuration

```bash
# Copier et renseigner les variables d'environnement
cp .env.example .env
# Editer .env : SEKOIA_INTAKE_KEY, AZURE_* (optionnel)

# Definir le perimetre a surveiller
# Editer config/scope.yaml : domaines racines, ranges IP, exclusions
```

### 2. Deploiement Docker (recommande)

```bash
docker compose build
docker compose up -d

# Voir les logs
docker compose logs -f surface-watch

# Dashboard web
# http://localhost:8080
```

### 3. Deploiement venv (alternatif)

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Lancement
python -m surface_watch --scan-now

# Dry-run (pas d'alertes envoyees)
python -m surface_watch --dry-run --scan-now

# Un seul collecteur
python -m surface_watch --collector dns
```

## Architecture

```
Scheduler (APScheduler)  +  Certstream listener  +  Flask dashboard
                    |
              Collectors
    dns / ct / azure / rdap / portscan / ipinfo
                    |
          Asset Graph (NetworkX + SQLite)
                    |
        +-----------+-----------+
        |           |           |
    Diff/Alert   Cartograph   Export
    (Sekoia)     (pyvis)    (JSON/GraphML)
```

## Sources de donnees

| Source | Methode | Frequence par defaut |
|--------|---------|---------------------|
| DNS | dnspython : A/AAAA/CNAME/MX/NS/TXT/SOA + brute-force subdomains | Toutes les 6h |
| Certificate Transparency | crt.sh API (batch) + certstream WebSocket (temps reel) | 6h batch + temps reel |
| Azure / Entra ID | Public IPs, DNS zones, App Services, App Registrations, domaines verifies | Toutes les heures |
| RDAP / WHOIS | Registrant, registrar, expiration, nameservers | Toutes les 24h |
| Port scan | nmap top 100 TCP + TLS cert grab | Toutes les 12h |
| IP enrichment | ipinfo.io API : ASN, organisation, pays (token optionnel) | Toutes les 12h |

## Sorties

### Alertes (Sekoia.io)
- Format CEF envoye via HTTP POST vers `intake.sekoia.io`
- Severites : CRITICAL (typosquatting, port critique expose), HIGH (nouveau sous-domaine/IP), MEDIUM (changement DNS), LOW (asset disparu)
- Fallback : fichier local `data/alerts.log`

### Cartographie
- **HTML interactif** : `data/map.html` (pyvis, vis.js embarqué — aucune dépendance CDN) — visible via le dashboard `/map`
  - Layout arborescent : domaine → sous-domaines → IPs/certificats → ports
  - Nœuds DNS records masqués (trop nombreux) — présents dans la base SQLite
  - Overlay légende flottante, compteur d'assets, bouton retour dashboard
- **JSON** : `data/graph.json` (format node-link NetworkX) — `/api/graph.json`
- **GraphML** : `data/graph.graphml` (compatible Gephi, yEd, Neo4j) — `/api/graph.graphml`

### Dashboard Web
- `http://localhost:8080/` — stats, derniers scans, alertes recentes
- `http://localhost:8080/map` — cartographie interactive
- API JSON : `/api/stats`, `/api/alerts`

## Configuration

### `config/scope.yaml`
Perimetre a surveiller :
```yaml
domains:
  - example.com
  - other-domain.fr
ip_ranges:
  - 198.51.100.0/24
exclusions:
  domains:
    - internal.example.com
  ip_ranges:
    - 10.0.0.0/8
```

### `config/settings.yaml`
Frequences de scan, ports a scanner, seuils d'alerte. Voir le fichier pour les details.

### `.env`
```
SEKOIA_INTAKE_KEY=your-key       # Obligatoire pour les alertes
AZURE_TENANT_ID=...              # Optionnel : collecteur Azure
AZURE_CLIENT_ID=...
AZURE_CLIENT_SECRET=...
DRY_RUN=false                    # true = pas d'alertes envoyees
```

## Collecteur Azure / Entra ID

Le collecteur Azure est **optionnel** et s'active automatiquement dès que les trois variables `AZURE_*` sont renseignées dans `.env`.

### Ce qu'il collecte

| Source Azure | Assets découverts |
|---|---|
| Public IP Addresses (toutes souscriptions) | `ip_address`, `cloud_resource` |
| Azure DNS Zones + Record Sets | `domain`, `subdomain`, `ip_address` |
| App Services | `subdomain` (hostnames custom + `*.azurewebsites.net`) |
| Entra ID — App Registrations | `cloud_resource` + URLs des redirect URIs / identifier URIs |
| Entra ID — Domaines vérifiés | `domain` |

### Créer un Service Principal (App Registration)

> Les commandes ci-dessous utilisent Azure CLI (`az`). Elles peuvent aussi être réalisées via le portail Azure.

```bash
# 1. Créer l'App Registration
az ad app create --display-name "surface-watch"

# 2. Créer le Service Principal associé
az ad sp create --id <APP_ID>

# 3. Créer un client secret (noter la valeur, elle ne s'affiche qu'une fois)
az ad app credential reset --id <APP_ID> --years 1
```

### Permissions nécessaires

**API Microsoft Graph** (pour Entra ID) — *Application permissions* :

| Permission | Portée | Justification |
|---|---|---|
| `Domain.Read.All` | Tenant | Lister les domaines vérifiés |
| `Application.Read.All` | Tenant | Lister les App Registrations |

```bash
# Ajouter les permissions Graph
az ad app permission add --id <APP_ID> \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions \
  dbb9058a-0e50-45d7-ae91-66909b5d4664=Role \
  9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30=Role

# Accorder le consentement admin
az ad app permission admin-consent --id <APP_ID>
```

**Rôles Azure RBAC** (pour les souscriptions) — rôle `Reader` suffisant :

```bash
# Assigner le rôle Reader sur chaque souscription à surveiller
az role assignment create \
  --assignee <APP_ID> \
  --role "Reader" \
  --scope "/subscriptions/<SUBSCRIPTION_ID>"
```

> Le rôle `Reader` est en lecture seule. Il donne accès aux Public IPs, DNS Zones et App Services.

### Renseigner `.env`

```bash
# Valeurs disponibles dans le portail : Azure AD > App Registrations > surface-watch
AZURE_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx   # "Directory (tenant) ID"
AZURE_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx   # "Application (client) ID"
AZURE_CLIENT_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Vérifier le collecteur

```bash
python -m surface_watch --collector azure --scan-now --no-web --no-certstream
```

Les assets découverts apparaissent dans le dashboard et dans `data/map.html` avec la couleur **verte** (cloud resources).

## CLI

```bash
python -m surface_watch [OPTIONS]

Options:
  --dry-run          Pas d'envoi d'alertes (simulation)
  --collector NAME   Executer un seul collecteur puis quitter
  --scan-now         Scan immediat avant de demarrer le scheduler
  --no-web           Desactiver le dashboard web
  --no-certstream    Desactiver le monitoring CT temps reel
```

## Couleurs de la cartographie

| Type | Couleur | Code |
|------|---------|------|
| Domain | Bleu corporate | `#003B5C` |
| Subdomain | Turquoise | `#00B2A9` |
| IP Address | Jaune | `#FFCD00` |
| Certificate | Lilas | `#9595D2` |
| Port/Service | Orange | `#E87722` |
| Cloud Resource | Vert | `#4CAF50` |

## Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```
