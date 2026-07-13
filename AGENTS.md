# Agent Instructions — proxdns

## Project structure
- `src/` — application code (`settings.py` is the single config entry point)
  - `proxmox.py` — Proxmox API client + VM→IP polling
  - `dns_server.py` — UDP DNS server (A / AAAA / PTR)
  - `http_server.py` — HTTP status page (`/`, `/json`, `/health`)
  - `app.py` — wiring: builds the client, runs the updater + servers
  - `state.py` — shared registry of resolved domains
- `tests/` — pytest
- `data/` — runtime state (gitignored; proxdns is stateless, so no volume is needed)
- `templates/` — static assets that ship inside the image
- `main.py` — thin entry point over `src/`

## Setup
All routine actions go through the `Makefile` — run `make help` to list targets.
```bash
make install           # create .venv and install dev/test deps
cp .env.example .env   # then fill in the values  (shortcut: make env)
```

## Running tests
```bash
make test
```

## Running the app
```bash
make run
```

## Conventions
- All config comes from ENV / `.env` (see `.env.example`); read via `src/settings.py`.
- Proxmox credentials (`PROXMOX_HOST` / `PROXMOX_USER` / `PROXMOX_PASSWORD`) have NO
  defaults — a missing var fails at startup with a clear message. Never hardcode
  creds or pass them via inline env vars; they go ONLY into `.env`.
- Code comments are in English.
- Repeated actions go through `make` targets (`install` / `test` / `run`).
- Python always runs inside a local `.venv`, created automatically by `make`.
- Tests are required for new code; in CI `build` depends on `test`.
- No `EXPOSE` in the Dockerfile; ports are published in docker-compose.
