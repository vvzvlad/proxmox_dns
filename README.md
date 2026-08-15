# proxmox_dns

**proxmox_dns** (which announces itself as *ProxDNS* in its own log output) is a
Python DNS service that resolves Proxmox VM domains to their IP addresses using
the Proxmox VE (PVE) API. It periodically polls the API for running VMs and
answers DNS queries (A / AAAA / PTR) accordingly, plus a small HTTP status page.

It is authoritative for an entire internal zone, so it is written to keep serving
whatever it already knows when PVE is unavailable: the API client is built lazily
and retried in the background, and the DNS and HTTP servers start regardless.

## Features
- Resolves Proxmox VM domains to their IPv4/IPv6 addresses (A / AAAA), with PTR.
- Optional subdomain resolution (`SUBDOMAINS`).
- HTTP status endpoints: `/` (HTML table), `/json`, `/health`.
- Periodic refresh with an adaptive interval.

## Quick start
Everything routine is wrapped in the `Makefile` (`make help` lists all targets):
```bash
make install                # create .venv + install dev/test deps
cp .env.example .env        # fill in the values (make env)
make test                   # run tests
make run                    # run the app
```
`make test` / `make run` create and reuse a local `.venv` automatically.

## Configuration (ENV / `.env`)
All config comes from the environment (see `.env.example`); read via
`src/settings.py`. Credentials have no defaults — a missing one fails at startup.

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `PROXMOX_HOST` | yes | — | Proxmox server address |
| `PROXMOX_USER` | yes | — | Proxmox API user (e.g. `proxmoxdns@pve`) |
| `PROXMOX_PASSWORD` | yes | — | Password for the API user |
| `LOG_LEVEL` | no | `INFO` | DEBUG / INFO / WARNING / ERROR / CRITICAL |
| `SUBDOMAINS` | no | `false` | Resolve subdomains to the parent's IP |
| `DOMAIN_SUFFIX` | no | `lc` | Suffix for the FQDN built from the VM name |

## Project structure
- `src/` — application code (`settings.py`, `proxmox.py`, `dns_server.py`, `http_server.py`, `app.py`, `state.py`)
- `main.py` — thin entry point
- `tests/` — pytest (gates the Docker build in CI)
- `ci/smoke.py` — the smoke gate CI runs against the built image
- `.gitea/workflows/` — CI (Gitea Actions)
- `data/` — runtime state (gitignored; proxmox_dns is stateless)
- `templates/` — static assets baked into the image

## CI
Two workflows in `.gitea/workflows`:

| Workflow | Trigger | What it does |
|----------|---------|--------------|
| `image-check-publish.yml` | push to `main`, manual | tests → build → **gate** → login → push |
| `tests.yml` | pull request | tests → build → **gate**, then throws the image away |

The image goes to `gitea.vvzvlad.xyz/projects/proxmox_dns`, tagged `:<sha>` first
and `:latest` second, so a push that fails half-way leaves production on the
previous image with its rollback point intact. The registry login happens only
after the gate is green.

### The smoke gate
`ci/smoke.py` runs between `docker build` and `docker push` — the last point at
which a broken image can still be stopped, because nothing downstream is manual:
the deployed container is auto-updated from `:latest`. The image serves DNS for
the whole internal zone, so an image that starts but does not answer does not
degrade the network, it removes name resolution from it. The unit tests prove the
*source* is good; only this proves the *image* is.

It checks that the image declares the command it is deployed with; that `curl`
is present **and runs** (the compose healthcheck shells out to it, and a
container that never reports healthy gets rolled back silently); that a run with
no configuration names all three missing variables and exits non-zero; that the
real command starts and logs all three startup markers **with PVE unreachable**;
that HTTP answers `/health`, `/json`, `/` and 404s anything else; that a real UDP
query on `127.0.0.1:53` comes back NXDOMAIN with a matching id, for an A question
and a PTR question both; that `.dockerignore` kept `tests/`, `.env`, `.venv` and
`.github/` out; and that every runtime dependency imports.

Two things about it are deliberate and are explained at length in its module
docstring. It boots the image with credentials pointing at `127.0.0.1`, because
an unreachable PVE is the regression under test rather than a limitation of CI.
And it publishes no ports: the CI job and the docker daemon are in different
network namespaces, so everything internal is reached with `docker exec`.

## Docker / Deploy
On prod, pull the prebuilt image via docker-compose (see `docker-compose.yml`) —
do not build on prod; the image is auto-updated from `:latest`.

proxmox_dns publishes raw UDP `:53` and an HTTP status port. DNS cannot go through
an HTTP router, so `:53` is mapped directly on the host while the status page is
also routed by Traefik. `docker-compose.yml` in this repo is the deploy template
and is kept in step with the running stack. Note that recreating the container
briefly takes `.lc` name resolution down for the whole network.

## Proxmox setup
Create a user with the required permissions:
```bash
pveum user add proxmoxdns@pve --password secretpass
pveum role add ProxmoxDNS --privs "VM.Audit,VM.Monitor"
pveum aclmod /vms --user proxmoxdns@pve --role ProxmoxDNS
```
