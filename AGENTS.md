# Agent Instructions — proxmox_dns

Authoritative DNS for the internal `.lc` zone, built from the VMs of one or more Proxmox VE
hosts, plus an HTTP status page. If the process dies before its servers bind, name resolution
for the whole internal network goes down.

## Layout
- `src/` — application code (`settings.py` is the single config entry point)
  - `proxmox.py` — Proxmox API client + VM→IP polling
  - `dns_server.py` — UDP DNS server (A / AAAA / PTR)
  - `http_server.py` — HTTP status page (`/`, `/json`, `/health`)
  - `app.py` — one updater thread per PVE host, the merge of their slices, the servers
  - `state.py` — shared registry of resolved domains
- `tests/` — pytest
- `ci/smoke.py` — the gate both workflows run against the built image
- `.gitea/workflows/` — CI (Gitea Actions); there is no `.github/workflows`
- `data/`, `templates/` — placeholders (the service is stateless)
- `main.py` — entry point

## Run and test
Routine actions go through the `Makefile` (`make help`); Python runs in a local `.venv`
that `make` creates.
```bash
make env                          # .env from .env.example, then fill it in
make pve-setup PVE=root@<host>    # role, user, API token and ACLs on one PVE host
make test
make run
```
Tests and the image are verified in CI (below).

## Conventions and invariants
- All config comes from ENV / `.env` (see `.env.example`), read via `src/settings.py`.
  Proxmox access is one variable, `PROXMOX_HOSTS`: a one-line JSON list, one entry per
  independent PVE host (`host` / `user` / `token_name` / `token_value`), API tokens only, no
  default, at least one entry. Credentials go only into `.env`.
- Code comments are in English. New code needs tests that go red when the invariant breaks.
- No `EXPOSE` in the Dockerfile; ports are published in docker-compose.
- The container runs as `app` (uid 1000): `entrypoint.sh` starts as root, chowns `/app/data`
  and `exec`s gosu. No `USER` directive in the Dockerfile; keep the entrypoint. `ci/smoke.py`
  checks PID 1's uid, since `docker exec` bypasses the entrypoint.
- No `cap_add: [NET_BIND_SERVICE]`: docker sets `net.ipv4.ip_unprivileged_port_start=0`, so
  uid 1000 binds 53 and 80. The in-container ports stay 53 and 80.
- `docker stop` needs both the `exec` in `entrypoint.sh` (python is PID 1) and the SIGTERM
  handler in `src/app.py` (PID 1 has no default signal dispositions).
- Nothing on the way to the DNS and HTTP threads may depend on Proxmox succeeding. The client
  is built lazily per host (`ensure_client()`), and every startup path tolerates `None`.
- Each host has its own updater thread and its own last-known slice; one host being down must
  neither drop its records nor delay another host. `initial_domains()` fetches all hosts
  concurrently under `INITIAL_FETCH_DEADLINE`, waits on the shutdown Event, and publishes
  itself (no return value for `run()` to assign). Keep the pre-fill: without it the DNS server
  answers NXDOMAIN for real names until the first poll. A late answer is published only while
  `HostState.has_published` is false.
- `merge_domains()` groups by host. A name claimed by two hosts goes to the host with the best
  entry (running with an address > running without > stopped; ties to the earlier
  `PROXMOX_HOSTS` entry), logged at WARNING. A name claimed twice on one host (`web-01` and
  `web-02` → `web.lc`) keeps every entry, logged at DEBUG. One address from two hosts is
  reported, never resolved. Within a name, entries are emitted best first: the DNS server
  answers with the first match.
- Publishing rebinds `state.servers_list`; never `clear()` + `extend()` (a query in between
  gets a cached NXDOMAIN). Read it as `state.servers_list`, never import the list object.
- `get_domains()` returns None only when the node listing fails; one failed node yields a
  partial list that the caller publishes. Known behaviour, pinned by a test.
- The status endpoints publish only `PUBLISHED_FIELDS` (`src/http_server.py`); they are
  unauthenticated.
- `docker-compose.yml` is an example with placeholders only, not the deployment (a Portainer
  stack is the source of truth).

## CI (Gitea Actions)
Two workflows in `.gitea/workflows`, kept as a matched pair:
- `image-check-publish.yml` — `push` to `main` + `workflow_dispatch`: tests, build, smoke
  gate, then login and push to `gitea.vvzvlad.xyz/projects/proxmox_dns`. Production follows
  `:latest` via the Portainer auto-update label.
- `tests.yml` — `pull_request` + `workflow_dispatch`: the same tests, image and gate, no
  credential, no push.

Before editing either:
- The `run:` bodies the two files share are byte-identical. Change one, change both.
- The registry login comes after the gate, and logout runs under `if: always()`.
- `:<sha>` is pushed before `:latest`.
- No `${{ }}` inside a `run:` body; values arrive through `env:`.
- Read the module docstring of `ci/smoke.py` before touching a check: it boots the image
  with unreachable PVE hosts on purpose and publishes no ports. `EXPECTED_*_TARGETS` must
  match the number of verdict rows.

## Limits for agents
- Tests: at most three times the code (`wc -l` of `tests/` against the code). Over the limit,
  still write the test you need, and in the same change go through the old tests: drop or merge
  duplicates and tests of implementation rather than behaviour.
- Comments explain the code as it is and why it is built this way. History ("used to", "after
  the review", "since the incident") goes into the commit message.
- This file stays under ~150 lines: only what an agent would get wrong without it. No decision
  history, incident logs or retelling of the code.
