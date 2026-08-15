# Agent Instructions — proxmox_dns

## Project structure
- `src/` — application code (`settings.py` is the single config entry point)
  - `proxmox.py` — Proxmox API client + VM→IP polling
  - `dns_server.py` — UDP DNS server (A / AAAA / PTR)
  - `http_server.py` — HTTP status page (`/`, `/json`, `/health`)
  - `app.py` — wiring: runs the updater + servers, builds the Proxmox client lazily
  - `state.py` — shared registry of resolved domains
- `tests/` — pytest
- `ci/` — `smoke.py`, the gate both workflows run against the built image
- `.gitea/workflows/` — CI (Gitea Actions); there is no `.github/workflows`
- `data/` — runtime state (gitignored; proxmox_dns is stateless, so no volume is needed)
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
- Tests are required for new code. An invariant with no test that goes red when it is
  broken is an intention, not an invariant — so when fixing a bug, check the new test
  by breaking the mechanism again and confirming it fails.
- No `EXPOSE` in the Dockerfile; ports are published in docker-compose.
- The Proxmox client is built LAZILY (`ensure_client()` in `src/app.py`) and every startup
  path tolerates it coming back `None`. proxmoxer authenticates inside `ProxmoxAPI(...)`,
  so building the client is a network call; nothing on the way to the DNS and HTTP threads
  may depend on it succeeding. This service answers DNS for the whole `.lc` zone, and a
  process that dies before those threads bind takes name resolution down with it.

## CI (Gitea Actions)
Two workflows in `.gitea/workflows`, and they must stay a matched pair:
- `image-check-publish.yml` — `push` to `main` + `workflow_dispatch`. Tests, build, gate,
  then login and push to `gitea.vvzvlad.xyz/projects/proxmox_dns`.
- `tests.yml` — `pull_request`. The same tests, the same image, the same gate, no
  credential and no push.

Rules worth knowing before editing either:
- The `run:` bodies the two files share are BYTE-IDENTICAL. Change one, change both.
- The registry login comes AFTER the gate, never before: until the gate is green the
  registry PAT has no business being on a runner shared with every other repository.
- `:<sha>` is pushed BEFORE `:latest`, so a half-failed push leaves production on the
  previous image with its rollback point intact.
- No `${{ }}` inside a `run:` body — values arrive through `env:`.
- `ci/smoke.py` runs against the built image between build and push. See its module
  docstring before touching a check; in particular it boots the image with an unreachable
  PVE ON PURPOSE, and it publishes no ports.
