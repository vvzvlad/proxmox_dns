# ProxDNS

**ProxDNS** is a Python DNS service that resolves Proxmox VM domains to their IP
addresses using the Proxmox VE (PVE) API. It periodically polls the API for
running VMs and answers DNS queries (A / AAAA / PTR) accordingly, plus a small
HTTP status page.

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
- `data/` — runtime state (gitignored; proxdns is stateless)
- `templates/` — static assets baked into the image

## Docker / Deploy
CI builds and pushes the image to `ghcr.io/vvzvlad/proxmox_dns` (tests must pass
first). On prod, pull the prebuilt image via docker-compose (see
`docker-compose.yml`) — do not build on prod; `watchtower` auto-updates `latest`.

ProxDNS publishes raw UDP `:53` and an HTTP status port, so it is exposed via
direct port mapping (not Traefik). Example (placeholders only):
```yaml
services:
  proxdns:
    image: ghcr.io/vvzvlad/proxmox_dns:latest
    container_name: proxdns
    restart: always
    ports:
      - "53:53/udp"
      - "8076:80/tcp"
    environment:
      PROXMOX_HOST: XXX
      PROXMOX_USER: XXX
      PROXMOX_PASSWORD: XXX
      TZ: Europe/Moscow
    labels:
      com.centurylinklabs.watchtower.enable: "true"
```

## Proxmox setup
Create a user with the required permissions:
```bash
pveum user add proxmoxdns@pve --password secretpass
pveum role add ProxmoxDNS --privs "VM.Audit,VM.Monitor"
pveum aclmod /vms --user proxmoxdns@pve --role ProxmoxDNS
```
