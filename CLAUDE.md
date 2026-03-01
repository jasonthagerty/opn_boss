# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Project Overview

OPNBoss is a standalone Python service that monitors OPNSense firewalls via their REST API, persists results to SQLite, and serves a real-time HTMX dashboard. It follows a collector → analyzer → persist → serve pipeline with four analysis domains.

### Core Capabilities

- **10 collectors** gather raw data from OPNSense REST endpoints (firmware, system, rules, gateways, interfaces, IDS, CARP, DNS, DHCP, routes)
- **4 analyzers** produce `Finding` objects with severity, remediation text, and evidence dicts
- **37 checks** across SEC (security), MW (multi-WAN), HA (high-availability/recovery), PERF (performance)
- **OPNBossService** orchestrates concurrent scans, persists snapshots and findings, handles offline firewalls
- **Finding suppression** — per (firewall_id, check_id), applied at persist time; suppressed findings are stored but excluded from counts and hidden by default in the dashboard
- **FastAPI + HTMX dashboard** with live SSE updates, finding filters, and inline suppress/unsuppress
- **APScheduler** for periodic scans; immediate scan via `POST /api/scan` or `opnboss scan`

### Architecture: Data Flow

```
config.yaml
    │
    ▼
OPNBossService.run_scan()
    │  (concurrent per enabled firewall)
    ▼
OPNSenseClient.probe()  ──offline──▶  _finalize_offline()  ──▶  HA-001 finding
    │ online
    ▼
_run_collectors()  [10 collectors, asyncio.gather]
    │
    ▼
analyzers[].analyze()  [4 analyzers → list[Finding]]
    │
    ▼
_persist_results()
    │  loads SuppressionDB for firewall
    │  marks each FindingDB.suppressed
    │  counts exclude suppressed findings
    ▼
SnapshotDB + FindingDB (SQLite)
    │
    ▼
SSE broadcast → dashboard refresh
```

## Development Commands

### Prerequisites

- **Python 3.12** (required — pyproject.toml `requires-python = ">=3.12"`)
- **uv** — `curl -LsSf https://astral.sh/uv/install.sh | sh`

### Setup

```bash
# Install with dev dependencies
uv pip install -e ".[dev]"

# Copy and configure
cp config/config.yaml.example config/config.yaml

# Set firewall credentials
export FW1_API_KEY=...
export FW1_API_SECRET=...
```

### Running

```bash
uv run opnboss serve          # dashboard + scheduler on :8080
uv run opnboss scan           # single immediate scan
uv run opnboss findings       # print recent findings to terminal
uv run opnboss status         # print firewall online/offline status
```

### Testing

```bash
# Unit tests only (no network, no running server)
uv run pytest tests/unit/ -q

# All tests (unit + integration via TestClient)
uv run pytest tests/ -q

# With coverage
uv run pytest --cov=opn_boss --cov-report=term tests/

# Single test file
uv run pytest tests/unit/test_analyzers/test_security.py -v
```

### Code Quality

```bash
uv run ruff check .           # lint
uv run ruff check --fix .     # lint + auto-fix
uv run mypy opn_boss          # type check
```

## Architecture

### Key Types (`opn_boss/core/types.py`)

```python
@dataclass
class Finding:
    check_id: str           # e.g. "SEC-002"
    title: str
    description: str
    severity: Severity      # CRITICAL | WARNING | INFO | OK
    category: Category      # SECURITY | MULTIWAN | HA_RECOVERY | PERFORMANCE
    firewall_id: str
    evidence: dict          # raw supporting data
    remediation: str | None # step-by-step fix instructions
    id: str                 # auto UUID
    ts: datetime            # auto UTC now
```

### Database Models (`opn_boss/core/database.py`)

| Table | Purpose |
|-------|---------|
| `firewall_state` | Online/offline status per firewall, last seen timestamp |
| `snapshots` | One per scan per firewall; severity counts (excluding suppressed) |
| `findings` | Individual check results; `suppressed` bool flag |
| `collector_runs` | Raw collector output (JSON), duration, success/error |
| `suppressions` | (firewall_id, check_id) pairs to silence findings; unique constraint |

**Migration**: `create_tables()` runs `ALTER TABLE findings ADD COLUMN suppressed` on startup (silently ignored if column exists — handles existing DBs).

### Collector Contract (`opn_boss/collectors/base.py`)

```python
class BaseCollector:
    collector_name: str   # must match key used by analyzers

    async def collect(self) -> CollectorResult:
        # call self._client (OPNSenseClient)
        # return CollectorResult(data={...}, success=True/False, ...)
```

Each collector maps to one OPNSense API area. The `data` dict structure is what analyzers read via `self._get_data(collector_results, "collector_name")`.

### Analyzer Contract (`opn_boss/analyzers/base.py`)

```python
class BaseAnalyzer:
    category: str

    def analyze(
        self, firewall_id: str, collector_results: dict[str, CollectorResult]
    ) -> list[Finding]:
        # produce Finding objects; return [] if data unavailable
        # never raise — log and return empty on errors
```

Analyzers are instantiated once in `OPNBossService.__init__` and called for every scan. They must be stateless.

### Check ID Conventions

| Prefix | Range | Domain |
|--------|-------|--------|
| SEC | 001–010 | Security |
| MW | 001–008 | Multi-WAN / Gateways |
| HA | 001–009 | High Availability / Recovery |
| PERF | 001–010 | Performance |

**HA-001** is special: generated by the service layer (not HaRecoveryAnalyzer) when a firewall is unreachable. It is suppressible like any other check.

### SSE Events

| Event | When |
|-------|------|
| `scan_started` | Beginning of run_scan() |
| `scan_completed` | All firewalls done |
| `scan_firewall_complete` | One firewall finished (includes counts) |
| `firewall_offline` | Firewall failed probe |

### Suppression Flow

1. `POST /api/suppressions {firewall_id, check_id}` — creates `SuppressionDB` row
2. Next scan: `_persist_results()` loads suppressed check_ids, sets `FindingDB.suppressed=True`, excludes from counts
3. Dashboard: `/partials/findings` filters out suppressed rows by default; `?show_suppressed=true` reveals them dimmed
4. `DELETE /api/suppressions/{id}` — removes suppression; next scan re-activates the check

## Code Organization Rules

When adding features:

1. **New collector**: create `opn_boss/collectors/<name>.py`, subclass `BaseCollector`, set `collector_name`, add to the list in `OPNBossService._run_collectors()`, add unit test in `tests/unit/test_collectors/`
2. **New check**: add `_<checkid>_<slug>()` method to the appropriate analyzer, call it in `analyze()`, document in README check reference table
3. **New analyzer domain**: create `opn_boss/analyzers/<domain>.py`, add to `OPNBossService._analyzers` list, add unit tests
4. **New API route**: create `opn_boss/api/routes/<name>.py`, register in `opn_boss/api/app.py`
5. **New DB column**: add to model, add `ALTER TABLE ... ADD COLUMN` migration in `create_tables()` with a bare `except: pass`
6. **Type hints**: required on all function signatures
7. **Async**: all I/O uses `async`/`await`; analyzers are sync (CPU-only)
8. **Tests**: unit tests must not make network calls — mock `OPNSenseClient` or pass fixture data directly to analyzers

## Testing Patterns

### Unit Testing Analyzers

Pass raw dicts directly — no DB, no HTTP:

```python
from opn_boss.core.types import CollectorResult
from opn_boss.analyzers.security import SecurityAnalyzer

def make_result(name, data):
    return CollectorResult(
        collector_name=name, firewall_id="fw1",
        success=True, data=data, duration_ms=0.0,
    )

def test_sec002_ids_down():
    results = {"ids": make_result("ids", {"enabled": True, "running": False})}
    findings = SecurityAnalyzer().analyze("fw1", results)
    f = next(f for f in findings if f.check_id == "SEC-002")
    assert f.severity == Severity.CRITICAL
```

### Integration Testing API Routes

```python
from fastapi.testclient import TestClient
from opn_boss.api.app import create_app
from opn_boss.core.config import load_config

@pytest.fixture(autouse=True)
def reset_db_globals():
    import opn_boss.core.database as db
    db._engine = None
    db._session_factory = None
    yield
    db._engine = None
    db._session_factory = None
```

**Important**: reset `_engine` and `_session_factory` between tests — they are module-level singletons. Without this, tests share the same DB file across different `tmp_path` fixtures.

## Configuration Reference

```yaml
firewalls:
  - firewall_id: str          # unique identifier used in DB and UI
    host: str                  # IP or hostname (no scheme, no port)
    api_key: str               # supports ${ENV_VAR} expansion
    api_secret: str
    role: "primary" | "backup"
    enabled: bool              # false = skip all scans, no alerts
    port: int                  # default 443
    verify_ssl: bool           # default false (self-signed certs common)

database:
  url: str                     # SQLAlchemy async URL, e.g. sqlite+aiosqlite:///data/opn_boss.db

scheduler:
  poll_interval_minutes: int   # default 15

api:
  host: str                    # default "0.0.0.0"
  port: int                    # default 8080
```

## Common Workflows

### Adding a New Check (Example: SEC-011 — TLS 1.0 Enabled)

1. Add method to `SecurityAnalyzer`:
   ```python
   findings += self._sec011_weak_tls(firewall_id, rules_data)
   ```

2. Implement the method:
   ```python
   def _sec011_weak_tls(self, firewall_id: str, rules: dict) -> list[Finding]:
       if not rules:
           return []
       # ... logic ...
       return [Finding(
           check_id="SEC-011",
           title="TLS 1.0 allowed",
           description="...",
           severity=Severity.WARNING,
           category=Category.SECURITY,
           firewall_id=firewall_id,
           evidence={"...": "..."},
           remediation="1. Go to ...\n2. ...",
       )]
   ```

3. Add unit test in `tests/unit/test_analyzers/test_security.py`
4. Add to README check reference table

### Suppressing a Noisy Finding

Via API:
```bash
curl -X POST http://localhost:8080/api/suppressions \
  -d "firewall_id=firewall2&check_id=SEC-002&reason=Backup FW intentionally runs no IDS"
```

Via dashboard: click **Suppress** on any non-OK finding row.

### Querying the Database Directly

```bash
# Latest findings per firewall
sqlite3 data/opn_boss.db "
  SELECT f.firewall_id, f.check_id, f.severity, f.suppressed
  FROM findings f
  JOIN snapshots s ON f.snapshot_id = s.id
  WHERE s.started_at = (
    SELECT MAX(started_at) FROM snapshots WHERE firewall_id = f.firewall_id
  )
  ORDER BY f.severity, f.firewall_id;
"

# Collector raw data
sqlite3 data/opn_boss.db "
  SELECT firewall_id, collector_name, data
  FROM collector_runs
  WHERE collector_name='gateways' AND firewall_id='firewall1'
  ORDER BY ts DESC LIMIT 1;
"
```

## Security Notes

- `config/config.yaml` contains credentials — it is gitignored
- OPNSense API keys/secrets grant full admin access; store in env vars or a secrets manager
- The dashboard has no authentication by default — bind to localhost or put behind a reverse proxy with auth
- `data/opn_boss.db` contains full scan history including raw firewall data — protect accordingly
