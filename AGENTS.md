# Agent Instructions — proxmox_dns

## Project structure
- `src/` — application code (`settings.py` is the single config entry point)
  - `proxmox.py` — Proxmox API client + VM→IP polling
  - `dns_server.py` — UDP DNS server (A / AAAA / PTR)
  - `http_server.py` — HTTP status page (`/`, `/json`, `/health`)
  - `app.py` — wiring: one updater thread per PVE host (each with its own lazily built
    client and its own slice of the zone), the merge of those slices, and the servers
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
- Proxmox access is ONE variable, `PROXMOX_HOSTS`: a JSON list with one entry per
  independent PVE host (`host` / `user` / `token_name` / `token_value`), API tokens
  only. No defaults and `min_length=1` — a missing or empty variable fails at startup
  with a clear message. Never hardcode creds or pass them via inline env vars; they go
  ONLY into `.env`.
- Code comments are in English.
- Repeated actions go through `make` targets (`install` / `test` / `run`).
- Python always runs inside a local `.venv`, created automatically by `make`.
- Tests are required for new code. An invariant with no test that goes red when it is
  broken is an intention, not an invariant — so when fixing a bug, check the new test
  by breaking the mechanism again and confirming it fails.
- No `EXPOSE` in the Dockerfile; ports are published in docker-compose.
- The container runs as the non-root user `app` (uid 1000). `entrypoint.sh` starts as
  root, chowns `/app/data` and drops privileges with `gosu`, so the Dockerfile carries no
  `USER` directive — do not add one and do not remove the entrypoint. `ci/smoke.py` checks
  the drop against PID 1's real uid, not against its own: the probes reach the container
  through `docker exec`, which walks straight past the entrypoint and arrives as root.
- Do NOT add `cap_add: [NET_BIND_SERVICE]` to docker-compose.yml. Binding 53 and 80 needs
  no capability inside a container: docker sets `net.ipv4.ip_unprivileged_port_start=0`,
  so uid 1000 binds both with an empty capability set (measured on the host this stack runs
  on, Docker 27.1.1). For the same reason the in-container ports stay
  53 and 80 — moving the service to high ports buys nothing.
- The Proxmox client is built LAZILY, per host (`ensure_client()` in `src/app.py`), and every
  startup path tolerates it coming back `None`. With API token auth `ProxmoxAPI(...)` makes NO
  network call — proxmoxer only stores the token and builds a header per request — so the first
  request to a host is now the startup fetch in `initial_domains()`. The rule that stands on
  that is unchanged and still load-bearing: nothing on the way to the DNS and HTTP threads may
  depend on Proxmox succeeding. This service answers DNS for the whole `.lc` zone, and a
  process that dies before those threads bind takes name resolution down with it.
- Each host gets its OWN updater thread and its OWN last-known slice of the zone, merged into
  `state.servers_list` by `merge_domains()`. One host being down must neither drop its own
  records nor delay another host's refresh — a shared loop would stall every host behind one
  that black-holes packets, at proxmoxer's 5 s timeout per guest-agent call. That holds for the
  STARTUP fetch too, which is the one path where the wait is downtime: `initial_domains()` runs
  the hosts concurrently under `INITIAL_FETCH_DEADLINE` and waits on the shutdown Event rather
  than on its fetch threads. Do not replace it with a loop, and do not delete it either — without
  the pre-fill the DNS server binds and answers NXDOMAIN for real names until the first poll,
  and an NXDOMAIN is cached by whoever asked. A host that misses the deadline is not held back
  and its answer is not thrown away: the fetch thread publishes it itself, but only while
  `HostState.has_published` is still false, so it can never overwrite a slice that host's own
  updater has already published. `initial_domains()` therefore publishes rather than returning a
  list for `run()` to assign — an assignment in `run()` would race that late publish.
- The merge groups entries BY HOST first. A name claimed by two hosts is resolved (the running
  VM wins, ranking each host by its best entry, ties going to the earlier entry in
  `PROXMOX_HOSTS`) and logged at WARNING; a name claimed twice on ONE host — `web-01` and
  `web-02` both give `web.lc` — is NOT a collision, keeps every entry, and is logged at DEBUG.
  Dropping one of those would take its address out of the zone and its PTR answer with it.
  One address arriving from two hosts is reported, never resolved: both A records are right.
  Within one name the entries are emitted BEST FIRST, by that same rank, in both branches of
  the merge. `src/dns_server.py` answers with the first matching entry, so the order IS the
  answer: unsorted, a stopped `web-01` ahead of a running `web-02` resolves `web.lc` to the
  `0.0.0.0` sentinel. The sort is stable, and it reorders only — every entry stays in the zone,
  so PTR is untouched.
- Publishing REBINDS `state.servers_list` rather than `clear()` + `extend()`: the in-place
  version has a window in which a query sees an empty zone and gets a cached NXDOMAIN back.
- `src/proxmox.py` `get_domains()` returns None only when the NODE LISTING fails — the caller's
  "keep the slice you have" signal. One node of a cluster failing while the others answer gives
  back a PARTIAL list instead, which the caller cannot tell from a complete one, so that node's
  guests leave the zone until it recovers. That predates multi-host support and was left alone
  on purpose; both candidate fixes (carrying the failed node's previous entries over, or
  returning None) have costs of their own and belong in their own change. See the docstring.
- The status endpoints publish an EXPLICIT field list (`PUBLISHED_FIELDS` in
  `src/http_server.py`), not the entry dict: they are unauthenticated, and dumping the dict
  would put every field ever added to an entry on a public page.

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
