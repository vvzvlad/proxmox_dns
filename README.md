# proxmox_dns

**proxmox_dns** (which announces itself as *ProxDNS* in its own log output) is a
Python DNS service that resolves Proxmox VM domains to their IP addresses using
the Proxmox VE (PVE) API. It periodically polls the API for running VMs and
answers DNS queries (A / AAAA / PTR) accordingly, plus a small HTTP status page.

It is authoritative for an entire internal zone, so it is written to keep serving
whatever it already knows when PVE is unavailable: the API client is built lazily
and retried in the background, and the DNS and HTTP servers start regardless. Each
configured host keeps its own last-known records, so one host going down costs its
freshness and nothing else.

## Features
- Resolves Proxmox VM domains to their IPv4/IPv6 addresses (A / AAAA), with PTR.
- Polls several INDEPENDENT PVE hosts and merges their VMs into one zone.
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
`src/settings.py`. Credentials have no defaults — a missing one fails at startup
with a message naming the variable, and for an error inside the JSON the message
names the entry and the field (`PROXMOX_HOSTS[1].token_value`).

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `PROXMOX_HOSTS` | yes | — | JSON list of PVE hosts to poll, one object per host |
| `LOG_LEVEL` | no | `INFO` | DEBUG / INFO / WARNING / ERROR / CRITICAL |
| `SUBDOMAINS` | no | `false` | Resolve subdomains to the parent's IP |
| `DOMAIN_SUFFIX` | no | `lc` | Suffix for the FQDN built from the VM name |

Each entry of `PROXMOX_HOSTS` has four fields, all required. **In `.env` the value must
be a single line** — dotenv has no line continuation, so a value wrapped across two
lines is cut at the newline and fails at startup as "not valid JSON", and so does
`PROXMOX_HOSTS=` left empty after clearing it:

```dotenv
PROXMOX_HOSTS=[{"host": "pve1.example", "user": "proxmoxdns@pve", "token_name": "dns", "token_value": "…"}, {"host": "pve2.example", "user": "proxmoxdns@pve", "token_name": "dns", "token_value": "…"}]
```

(In `docker-compose.yml` a YAML block scalar — `PROXMOX_HOSTS: >-` — lets the same
value be written across several lines and still arrive as one string.)

The hosts are INDEPENDENT endpoints, each with its own token, and their VMs are merged
into one zone. A multi-node *cluster* is a single entry: one endpoint already answers
for every node in it. At least one entry is required — an empty list fails at startup
for the same reason a missing variable does.

Each host is polled on its own thread, so one host being down neither drops its own
last-known records nor delays anybody else's refresh, and the startup fetch runs every
host at once under a deadline rather than one after another.

### When two things claim the same name or the same address

The domain is the VM name's first segment, and nothing coordinates naming between
standalone hosts, so two kinds of clash are possible and they are handled differently.

**One name, two hosts.** The **running** VM wins; among equally good candidates
(running with an address > running with no readable address > stopped) the host listed
first in `PROXMOX_HOSTS` does. The winner is the *host*: every entry it has for that
name is served, so a host that wins does not lose its own duplicates in the process.
Each such collision is logged at WARNING with both hosts and both vmids, and the `Host`
column on the status page says which host each name came from.

**One name, one host** — `web-01` and `web-02` both become `web.lc` — is not a
collision and is not resolved. Both entries stay in the zone, and the *other* guest
keeps its PTR record, which it would lose if the entry were dropped. It is logged at
DEBUG, not WARNING. The name resolves to the **best** of them by the same ranking as
above (running with an address > running with no readable address > stopped), so a
stopped `web-01` no longer answers `web.lc` with `0.0.0.0` while `web-02` is up;
between equally good ones it is the first the host reported.

**One address, two hosts.** Independent hosts usually run overlapping RFC1918 ranges,
so two guests with different names can legitimately carry the same address. Both are
served — picking a winner would be guessing — but a PTR query for that address can only
be answered with one of the names, and which one is arbitrary. That is logged at
WARNING naming both guests; if you need reverse lookups to be unambiguous, the fix is
on the network side, not in this service.

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

It checks that the image declares the command and the entrypoint it is deployed
with; that `curl` is present **and runs** (the compose healthcheck shells out to
it, and a container that never reports healthy gets rolled back silently); that a
run with no configuration names the missing variable and exits non-zero;
that the real command starts and logs all three startup markers **with PVE
unreachable**; that **PID 1 serves as uid 1000 and not as root**; that HTTP
answers `/health`, `/json`, `/` and 404s anything else; that a real UDP query on
`127.0.0.1:53` comes back NXDOMAIN with a matching id, for an A question and a
PTR question both; that `.dockerignore` kept `tests/`, `.env`, `.venv` and
`.gitea/` out; that **every configured host is really polled**, and not just the
first one; and that every runtime dependency imports.

The uid check reads `/proc/1/status` rather than its own uid on purpose: the
probes arrive through `docker exec`, which never goes through the entrypoint, so
they run as root on a perfectly good image. PID 1 is the only process in the
container that came through the privilege drop.

Two things about it are deliberate and are explained at length in its module
docstring. It boots the image with **two** `PROXMOX_HOSTS` entries at **two
different** unroutable addresses — `192.0.2.1` and `198.51.100.1`, RFC 5737
documentation ranges nothing anywhere answers on. All three properties carry
weight. An unreachable PVE is the regression under test rather than a limitation
of CI; more than one host is the configuration the service actually runs in, so a
regression that only shows up with N>1 cannot slip through; and the addresses
**must not be the same**, because the per-host poll check counts the host names
appearing in the service's own failure lines. With both entries on one address it
cannot tell a healthy image from one that only ever polls `_hosts[0]` — it would
stay green while proving nothing. Do not "simplify" the two addresses into one.
And it publishes no ports: the CI job and the docker daemon are in different
network namespaces, so everything internal is reached with `docker exec`.

## Docker / Deploy
On prod, pull the prebuilt image via docker-compose (see `docker-compose.yml`) —
do not build on prod; the image is auto-updated from `:latest`.

proxmox_dns publishes raw UDP `:53` and an HTTP status port. DNS cannot go through
an HTTP router, so `:53` is mapped directly on the host while the status page is
also routed by Traefik. `docker-compose.yml` in this repo is an EXAMPLE — an
illustration of how the service is configured, meant to be copied as a starting
point. It is deliberately NOT kept in sync with the running stack, and must not
be: the Portainer stack that actually runs is the only source of truth for its
variables, volume paths, domain and image tag. A difference between the two is
therefore not a defect to reconcile — do not "fix" this file against a running
deployment, and do not change a deployment to match it. Every value in it is a
placeholder; see the header of the file itself. Note that recreating the
container briefly takes `.lc` name resolution down for the whole network.

The container serves as the unprivileged user `app` (uid 1000): `entrypoint.sh`
starts as root, chowns `/app/data` and drops privileges with `gosu` before python
runs — so the Dockerfile carries no `USER` directive and must not gain one. It
needs **no** `cap_add: [NET_BIND_SERVICE]` for ports 53 and 80, because docker
sets `net.ipv4.ip_unprivileged_port_start=0` inside the container and there are no
privileged ports in there to begin with.

## Proxmox setup
Repeat this on **every** host in `PROXMOX_HOSTS`: they are independent machines with
independent user databases, so each one needs its own user, its own token and its own
ACLs.

```bash
# 1. A user and a read-only role for it.
pveum user add proxmoxdns@pve
pveum role add ProxmoxDNS --privs "VM.Audit,VM.Monitor"
pveum acl modify /vms --user proxmoxdns@pve --role ProxmoxDNS

# 2. An API token for that user. THE TOKEN VALUE IS PRINTED ONCE AND NEVER AGAIN —
#    copy it out of this output; a lost one can only be replaced, not recovered.
pveum user token add proxmoxdns@pve dns --privsep 1

# 3. THE STEP EVERYONE MISSES. A token defaults to privilege separation, which makes
#    its effective permissions the INTERSECTION of the user's and its own — and its own
#    are empty until it is given an ACL here.
pveum acl modify /vms -token 'proxmoxdns@pve!dns' -role ProxmoxDNS
```

Skipping step 3 does not produce an error anywhere. The token authenticates perfectly
and every listing endpoint answers with an **empty list**, so the host silently
contributes no names at all and the zone quietly shrinks. That is why the service logs
a WARNING naming the host whenever a host reports no nodes — if you see it and the host
does have VMs, this is the reason. (`--privsep 0` also works and skips step 3, at the
price of a token that carries the user's full permissions.)

Then put `host`, `user` (`proxmoxdns@pve`), `token_name` (`dns`) and the `token_value`
from step 2 into that host's entry in `PROXMOX_HOSTS`.
