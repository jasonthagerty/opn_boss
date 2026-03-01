# OPNBoss

OPNSense Analyzer & Recommendation Service. Scans OPNSense firewalls via their REST API, stores results in SQLite, and serves a real-time web dashboard with actionable findings, remediation guidance, and AI-powered policy analysis.

## Features

- **Multi-firewall support** — scan primary and backup firewalls concurrently
- **37 automated checks** across Security, Multi-WAN, HA/Recovery, and Performance categories
- **Real-time dashboard** — HTMX-powered, updates live via Server-Sent Events
- **Finding suppression** — silence known/expected findings per firewall per check
- **Scheduled scanning** — configurable polling interval via APScheduler
- **Offline detection** — graceful handling of unreachable firewalls with HA-001 alert
- **Policy analysis** — local LLM (Ollama) explains what traffic is allowed/denied in plain English
- **What-if queries** — ask "would SSH from 1.2.3.4 be allowed?" and get a reasoned answer with log evidence
- **REST API** — full JSON API alongside the dashboard

## Quick Start

### With uv (local)

```bash
# Install uv if not already installed
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and enter the project
cd opn_boss

# Copy and edit config
cp config/config.yaml.example config/config.yaml
$EDITOR config/config.yaml

# Set API credentials
export FW1_API_KEY=your_key
export FW1_API_SECRET=your_secret

# Run the dashboard
uv run opnboss serve
```

### With Docker

```bash
# Copy and edit config
cp config/config.yaml.example config/config.yaml
$EDITOR config/config.yaml

# Run with docker compose
FW1_API_KEY=your_key FW1_API_SECRET=your_secret docker compose up -d
```

Dashboard: http://localhost:8080

## Installation

**Requirements**: Python 3.12+, uv

```bash
# Development install (editable + dev tools)
uv pip install -e ".[dev]"

# Production install
uv pip install -e .
```

## Configuration

Copy `config/config.yaml.example` to `config/config.yaml`:

```yaml
firewalls:
  - firewall_id: "firewall1"
    host: "192.168.1.1"           # OPNSense management IP
    api_key: "${FW1_API_KEY}"     # Env var expansion supported
    api_secret: "${FW1_API_SECRET}"
    role: "primary"               # primary | backup
    enabled: true

  - firewall_id: "firewall2"
    host: "192.168.1.2"
    api_key: "${FW2_API_KEY}"
    api_secret: "${FW2_API_SECRET}"
    role: "backup"
    enabled: true

database:
  url: "sqlite+aiosqlite:///data/opn_boss.db"

scheduler:
  poll_interval_minutes: 15

api:
  host: "0.0.0.0"
  port: 8080

# Optional: local LLM for policy analysis (requires Ollama)
llm:
  enabled: true
  model: "phi3:mini"          # or llama3.2:3b, mistral:7b, qwen2.5:3b
  base_url: "http://localhost:11434"
  timeout_seconds: 120.0
```

**API credentials**: In OPNSense → System → Access → Users, create a user and generate an API key/secret pair.

Set `enabled: false` on a firewall to silence all alerts without removing it from config.

## Docker Deployment

```bash
# Build locally
docker build -t opn-boss .

# Or pull from GitHub Container Registry
docker pull ghcr.io/jasonthagerty/opn-boss:latest

# Run with compose (recommended)
docker compose up -d

# View logs
docker compose logs -f opn_boss
```

The compose file mounts `./config/config.yaml` read-only and persists the SQLite database in a named volume (`opn_boss_data`).

### With Ollama (policy analysis)

Uncomment the `ollama` service in `docker-compose.yml` and set `llm.base_url: "http://ollama:11434"` in your config:

```bash
docker compose up -d
docker compose exec ollama ollama pull phi3:mini
```

## CLI Commands

```bash
# Start dashboard + scheduler
uv run opnboss serve

# Run a single scan immediately
uv run opnboss scan

# List recent findings
uv run opnboss findings

# Show firewall status
uv run opnboss status
```

## Dashboard

The web dashboard at http://localhost:8080 provides:

- **Firewall cards** — online/offline status, severity counts, last scan time
- **Findings table** — all findings from latest snapshots, sortable by severity
- **Suppression** — click "Suppress" on any finding to silence it; toggle "Show suppressed" to review
- **Scan on demand** — "Scan Now" button in the nav bar
- **Live updates** — SSE connection auto-refreshes cards and findings on scan completion
- **Policy Analysis** — per-firewall tab with LLM-generated policy summary and what-if query form

## Policy Analysis (Local LLM)

OPNBoss can generate a plain-English description of your firewall policy and answer what-if questions using a locally-running LLM via [Ollama](https://ollama.ai). No data leaves your network.

**Setup:**
```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a model (phi3:mini is fast, ~2GB)
ollama pull phi3:mini

# Enable in config
# llm:
#   enabled: true
#   model: "phi3:mini"
```

**Usage:** Navigate to any firewall's detail page → **Policy Analysis** tab → click **Generate Analysis** or type a what-if question.

**Supported models:** Any Ollama-compatible model — `phi3:mini`, `llama3.2:3b`, `mistral:7b`, `qwen2.5:3b`, etc. Smaller models are faster; larger models give more nuanced answers.

## API

```
GET  /api/firewalls                        Firewall states
GET  /api/snapshots                        Recent snapshots (filterable by firewall_id)
GET  /api/snapshots/{id}/findings          Findings for a specific snapshot
POST /api/scan                             Trigger immediate scan
GET  /api/suppressions                     List all suppressions (JSON)
POST /api/suppressions                     Create suppression {firewall_id, check_id, reason?}
DELETE /api/suppressions/{id}             Remove suppression
GET  /api/policy/{firewall_id}/summary    Latest policy summary (JSON)
POST /api/policy/{firewall_id}/analyze    Generate/regenerate policy summary (HTMX)
POST /api/policy/{firewall_id}/whatif     Submit what-if query (HTMX)
GET  /api/policy/{firewall_id}/history    Past what-if queries (JSON)
GET  /api/events                           SSE stream
```

## Check Reference

### Security (SEC)

| Check | Severity | Description |
|-------|----------|-------------|
| SEC-001 | OK/WARNING | Firmware up to date / outdated |
| SEC-002 | CRITICAL | IDS/IPS service down |
| SEC-003 | CRITICAL | Admin UI accessible from WAN |
| SEC-004 | WARNING | Any-to-any firewall rules present |
| SEC-005 | INFO | Anti-lockout rule status |
| SEC-006 | WARNING | SSH exposed on WAN |
| SEC-007 | WARNING | DNS recursion accessible from WAN |
| SEC-008 | WARNING | IDS enabled but not on WAN interface |
| SEC-009 | WARNING | No default deny rule at end of ruleset |
| SEC-010 | INFO | High number of disabled rules |

### Multi-WAN (MW)

| Check | Severity | Description |
|-------|----------|-------------|
| MW-001 | CRITICAL | Primary WAN gateway down |
| MW-002 | WARNING | Backup WAN gateway down |
| MW-003 | INFO | Single WAN (no redundancy) |
| MW-004 | WARNING | High gateway latency |
| MW-005 | WARNING | High packet loss on gateway |
| MW-006 | INFO | Gateway failover group configured |
| MW-007 | WARNING | Asymmetric routing detected |
| MW-008 | OK | All WAN gateways healthy |

### HA & Recovery (HA)

| Check | Severity | Description |
|-------|----------|-------------|
| HA-001 | CRITICAL | Firewall unreachable (generated by service layer) |
| HA-002 | WARNING | CARP state unexpected |
| HA-003 | CRITICAL | pfsync interface down |
| HA-004 | WARNING | IPv6 RA conflict (backup firewall radvd active) |
| HA-005 | INFO | CARP advertising skew |
| HA-006 | WARNING | HA peer state mismatch |
| HA-007 | INFO | pfsync state table sync lag |
| HA-008 | OK | HA pair healthy |
| HA-009 | WARNING | CARP INIT state detected |

### Performance (PERF)

| Check | Severity | Description |
|-------|----------|-------------|
| PERF-001 | WARNING | High CPU utilization |
| PERF-002 | WARNING | High memory utilization |
| PERF-003 | WARNING | High disk utilization |
| PERF-004 | CRITICAL | State table >85% full |
| PERF-005 | WARNING | State table >70% full |
| PERF-006 | INFO | DHCP lease pool utilization |
| PERF-007 | WARNING | Interface errors/drops |
| PERF-008 | INFO | Uptime (recently rebooted) |
| PERF-009 | OK | Performance within normal bounds |
| PERF-010 | INFO | Large routing table |

## Project Structure

```
opn_boss/
├── opn_boss/
│   ├── core/
│   │   ├── config.py           # Pydantic config models (AppConfig, LLMConfig), env var expansion
│   │   ├── database.py         # SQLAlchemy async models (Snapshot, Finding, Suppression, PolicySummary, WhatIfQuery)
│   │   ├── types.py            # Finding, Severity, Category, SnapshotSummary
│   │   ├── exceptions.py       # ConfigError, CollectorError, LLMUnavailableError
│   │   └── logging_config.py   # Structured logging setup
│   ├── opnsense/
│   │   └── client.py           # Async httpx client, probe(), OPNSense REST API
│   ├── collectors/             # 12 collectors (one per data domain)
│   │   ├── base.py             # BaseCollector with collect() contract
│   │   ├── firmware.py         # Firmware version, update status
│   │   ├── system.py           # CPU, memory, uptime, disk
│   │   ├── firewall_rules.py   # Rule count, disabled rules, WAN rules
│   │   ├── nat_rules.py        # Port forwards (DNAT) and outbound NAT (SNAT)
│   │   ├── firewall_logs.py    # Recent firewall log entries (for LLM evidence)
│   │   ├── gateways.py         # Gateway status, latency, loss
│   │   ├── interfaces.py       # Interface status, IPs, media
│   │   ├── ids.py              # IDS/IPS service and rule status
│   │   ├── carp.py             # CARP/VRRP state, pfsync
│   │   ├── dns.py              # DNS resolver config
│   │   ├── dhcp.py             # DHCP leases, pool utilization
│   │   └── routes.py           # Routing table
│   ├── analyzers/              # 4 analyzers producing Finding objects
│   │   ├── base.py             # BaseAnalyzer with analyze() contract
│   │   ├── security.py         # SEC-001..010
│   │   ├── multiwan.py         # MW-001..008
│   │   ├── ha_recovery.py      # HA-002..009
│   │   └── performance.py      # PERF-001..010
│   ├── llm/                    # Local LLM policy analysis
│   │   ├── client.py           # OllamaClient (async httpx wrapper)
│   │   ├── formatter.py        # PolicyFormatter (rules/NAT/routes → compact text)
│   │   ├── prompts.py          # Prompt builders (summary, what-if, log evidence)
│   │   └── service.py          # PolicyAnalysisService orchestrator
│   ├── service/
│   │   └── main.py             # OPNBossService orchestrator, scan loop, DB persistence
│   ├── scheduler/
│   │   └── jobs.py             # APScheduler periodic scan job
│   ├── api/
│   │   ├── app.py              # FastAPI factory, lifespan, router registration
│   │   ├── dependencies.py     # get_service() dependency
│   │   ├── models.py           # Pydantic response models
│   │   ├── sse.py              # SSEManager for broadcast
│   │   ├── routes/
│   │   │   ├── dashboard.py    # GET /, /firewall/{id}, /partials/findings
│   │   │   ├── firewalls.py    # GET /api/firewalls
│   │   │   ├── snapshots.py    # GET /api/snapshots[/{id}/findings]
│   │   │   ├── scan.py         # POST /api/scan
│   │   │   ├── suppressions.py # POST/GET/DELETE /api/suppressions
│   │   │   ├── policy.py       # GET/POST /api/policy/{id}/*
│   │   │   └── sse.py          # GET /api/events (SSE stream)
│   │   ├── static/js/
│   │   │   └── htmx.min.js     # HTMX 1.9.12 (local, no CDN dependency)
│   │   └── templates/
│   │       ├── base.html
│   │       ├── dashboard.html
│   │       ├── firewall_detail.html
│   │       └── partials/       # HTMX partials (findings_table, policy_summary, whatif_card, llm_error, ...)
│   └── cli/
│       └── commands.py         # Typer CLI (serve, scan, findings, status)
├── config/
│   ├── config.yaml.example
│   └── config.yaml             # (gitignored, created by user)
├── data/
│   └── opn_boss.db             # SQLite (auto-created)
├── tests/
│   ├── unit/
│   │   ├── test_analyzers/     # Per-analyzer unit tests
│   │   ├── test_collectors/    # Collector contract tests
│   │   ├── test_llm/           # LLM formatter, prompt, and client tests
│   │   └── test_core/          # Config, types, database model tests
│   └── integration/
│       └── test_api/           # FastAPI TestClient integration tests
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
└── pyproject.toml
```

## Development

```bash
# Run unit tests only
uv run pytest tests/unit/

# Run all tests (unit + integration)
uv run pytest tests/

# Run with coverage
uv run pytest --cov=opn_boss --cov-report=term tests/

# Lint
uv run ruff check .

# Type check
uv run mypy opn_boss
```

## CI/CD

Five GitHub Actions workflows run automatically:

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| **CI** | Push/PR to main/develop | ruff + mypy + pytest + Codecov; auto-creates issue on main failure |
| **Docker Build** | After CI passes on main, version tags | Builds multi-arch image (amd64/arm64), publishes to GHCR |
| **Security Scan** | Push/PR + weekly Monday | bandit + safety dependency vulnerability check |
| **Claude Code** | @claude mention in issues/PRs | Interactive AI coding assistant |
| **Claude Code Review** | Pull requests opened/updated | Automated AI code review comment |

The Docker image is published to `ghcr.io/jasonthagerty/opn-boss`.

## License

MIT
