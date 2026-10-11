# Makefile — single entry point for every repeated action in this project.
# Run `make` (or `make help`) to list the available targets.

# --- Configuration -----------------------------------------------------------
VENV   ?= .venv
PY     := $(VENV)/bin/python
# Both go through `python -m` rather than the console scripts: the scripts carry a shebang with
# the absolute path of the venv they were created in, so a moved or copied project directory
# leaves them pointing at an interpreter that is no longer there.
PIP    := $(VENV)/bin/python -m pip
PYTEST := $(VENV)/bin/python -m pytest

.DEFAULT_GOAL := help

# --- Help --------------------------------------------------------------------
.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

# --- Environment -------------------------------------------------------------
# The project ALWAYS runs inside a local .venv, created automatically on first
# use and reused after — the system Python is never used directly.
.PHONY: venv
venv: $(VENV)/bin/python ## Create the local virtualenv (.venv) if missing

$(VENV)/bin/python:
	python3 -m venv $(VENV)

# Sentinel: dependencies are (re)installed only when a requirements file changes.
$(VENV)/.deps-installed: requirements-dev.txt requirements.txt | $(VENV)/bin/python
	$(PIP) install -r requirements-dev.txt
	touch $@

.PHONY: install
install: $(VENV)/.deps-installed ## Create .venv (if missing) and install dev/test deps

.PHONY: env
env: ## Create .env from the template if it does not exist
	@test -f .env || cp .env.example .env

# --- Develop -----------------------------------------------------------------
.PHONY: test
test: install ## Run the test suite (auto-creates .venv if missing)
	$(PYTEST)

.PHONY: run
run: install ## Run the application (auto-creates .venv if missing)
	$(PY) main.py

# --- Proxmox -----------------------------------------------------------------
# PVE 8 needs PVE_PRIVS=VM.Audit,VM.Monitor. A new token's value is printed only once and goes
# into that host's PROXMOX_HOSTS entry.
PVE_PRIVS ?= VM.Audit,VM.GuestAgent.Audit

.PHONY: pve-setup
pve-setup: ## Create the proxmoxdns user, role and API token on PVE=root@<host>
	@test -n "$(PVE)" || { echo "usage: make pve-setup PVE=root@<host>" >&2; exit 1; }
	ssh $(PVE) 'set -e; \
		pveum role add ProxmoxDNS --privs $(PVE_PRIVS) \
			|| pveum role modify ProxmoxDNS --privs $(PVE_PRIVS); \
		pveum user add proxmoxdns@pve || true; \
		pveum acl modify /vms --user proxmoxdns@pve --role ProxmoxDNS; \
		pveum user token add proxmoxdns@pve dns --privsep 1 \
			|| echo "token proxmoxdns@pve!dns already exists; its value is printed only on creation"; \
		pveum acl modify /vms --token "proxmoxdns@pve!dns" --role ProxmoxDNS'

# --- Housekeeping ------------------------------------------------------------
.PHONY: clean
clean: ## Remove the venv and Python caches
	rm -rf $(VENV) .pytest_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
