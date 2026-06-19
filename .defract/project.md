---
defract:
  version: 1
  generated_at: "2026-06-19T00:00:00Z"
  updated_at: "2026-06-19T00:00:00Z"
  source: extracted
---

# Project Profile

## Overview

dnsmenace is a Python CLI tool for querying DNS servers from any country in the world, aimed at security researchers and network administrators. It supports geo-diff comparison, DNS-over-HTTPS, subdomain bruteforce, email security record checks, zone transfer testing, live monitoring, and geolocation mapping.

## Stack

- **Runtime**: Python 3.11+
- **CLI framework**: Typer 0.9+ with Rich markup
- **DNS**: dnspython 2.4+
- **HTTP client**: httpx 0.25+ (async, used for DoH and geolocation APIs)
- **Output/UI**: Rich 13+ (tables, progress bars, live dashboards, trees)
- **Data validation**: Pydantic 2.5+
- **Build backend**: Hatchling
- **Linter**: Ruff (target py311, line-length 100, rule set: E,F,I,N,W,UP,B,C4,SIM)
- **Type checker**: mypy strict mode
- **Testing**: pytest + pytest-asyncio

## Conventions

- Single-module layout — all application code lives in `dnsmenace.py` — evidence: `[tool.hatch.build.targets.wheel] py-modules = ["dnsmenace"]`
- Async-first for I/O — DNS queries and HTTP calls use `asyncio`/`httpx.AsyncClient`, driven with `asyncio.run()` at command boundaries — evidence: `async def query_dns`, `async def fetch_nameservers`, etc.
- Dataclasses for domain types — `NameServer`, `DNSResult`, `SecurityCheck`, `DoHProvider` — evidence: `@dataclass` throughout `dnsmenace.py`
- Strict typing — `from __future__ import annotations`, `mypy strict = true`, `warn_return_any`, all public functions are annotated — evidence: `pyproject.toml [tool.mypy]`
- Rich console for all user-facing output — no bare `print()`, all output goes through `console = Console()` — evidence: consistent use throughout `dnsmenace.py`
- Typer `Annotated` style for CLI options — evidence: every command uses `Annotated[type, typer.Option(...)]`
- Entry point: `dnsmenace = "dnsmenace:app"` — evidence: `pyproject.toml [project.scripts]`

## File Structure

```
dnsmenace/
├── dnsmenace.py        # Entire application: CLI commands, async DNS logic, display functions
├── pyproject.toml      # Project metadata, dependencies, ruff/mypy config, build backend
├── README.md           # Usage docs and command reference
└── .gitignore          # Standard Python ignores (.venv, __pycache__, dist, etc.)
```

## Key Dependencies

### Runtime
- `typer[all]>=0.9.0` — CLI framework with argument parsing and help generation
- `rich>=13.0.0` — terminal UI: tables, progress bars, live dashboards, panels, trees
- `dnspython>=2.4.0` — DNS resolution, async resolver, zone transfer, DoH wire format
- `httpx>=0.25.0` — async HTTP for DoH queries and ip-api.com geolocation
- `iso3166>=2.1.0` — country code validation and name lookup
- `pydantic>=2.5.0` — data validation

### Dev
- `pytest>=7.4.0` — test runner
- `pytest-asyncio>=0.21.0` — async test support
- `ruff>=0.1.0` — linter and import sorter
- `mypy>=1.7.0` — static type checker

## Build Commands

| Command | Description |
|---------|-------------|
| `pip install -e ".[dev]"` | Install in editable mode with dev dependencies |
| `uv pip install .` | Install via uv (recommended in README) |
| `ruff check .` | Run linter |
| `mypy dnsmenace.py` | Run type checker |
| `pytest` | Run tests |
| `dnsmenace --help` | Show CLI help |

## Project-Specific Notes

- **External data source**: nameserver lists are fetched at runtime from `https://public-dns.info/nameserver/{cc}.json`; geolocation from `http://ip-api.com/json/{ip}` (no API key required).
- **DoH implementation**: uses RFC 8484 GET with base64url-encoded DNS wire format, not the JSON-based API.
- **Subdomain wordlist**: 150+ common subdomains are hardcoded in `SUBDOMAIN_WORDLIST` (`dnsmenace.py:137`); custom wordlists can be passed via `--wordlist`.
- **GLOBAL_DNS_SERVERS**: 8 well-known public resolvers hardcoded for `propagation` and `watch` commands (`dnsmenace.py:106`).
- **No tests yet**: `pytest` and `pytest-asyncio` are listed as dev dependencies but no test files exist in the repo.
- **Version**: 3.0.0 — described as "Security Research Edition" with advanced features added in recent commits.
