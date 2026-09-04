import json

import pytest
from pydantic import ValidationError

from src.settings import Settings

TWO_HOSTS = [
    {"host": "pve1.example", "user": "dns@pve", "token_name": "dns", "token_value": "uuid-1"},
    {"host": "pve2.example", "user": "dns@pve", "token_name": "dns", "token_value": "uuid-2"},
]


def test_loads_several_hosts_from_env(monkeypatch):
    """PROXMOX_HOSTS is one JSON list; pydantic-settings parses it into the models.

    Several entries, because a single-host list would pass just as well against code
    that quietly kept only the first one.
    """
    monkeypatch.setenv("PROXMOX_HOSTS", json.dumps(TWO_HOSTS))
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("SUBDOMAINS", "true")
    s = Settings(_env_file=None)
    assert [h.host for h in s.proxmox_hosts] == ["pve1.example", "pve2.example"]
    assert s.proxmox_hosts[0].user == "dns@pve"
    assert s.proxmox_hosts[0].token_name == "dns"
    assert s.proxmox_hosts[1].token_value == "uuid-2"
    assert s.log_level == "DEBUG"
    assert s.subdomains is True


def test_defaults(monkeypatch):
    monkeypatch.setenv("PROXMOX_HOSTS", json.dumps(TWO_HOSTS[:1]))
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    monkeypatch.delenv("SUBDOMAINS", raising=False)
    monkeypatch.delenv("DOMAIN_SUFFIX", raising=False)
    s = Settings(_env_file=None)
    assert s.log_level == "INFO"
    assert s.subdomains is False
    assert s.domain_suffix == "lc"


def test_missing_variable_fails(monkeypatch):
    monkeypatch.delenv("PROXMOX_HOSTS", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_empty_host_list_fails(monkeypatch):
    """`[]` parses fine and would start a server that can never learn a single name.

    min_length=1 is what turns that into a startup failure naming the variable,
    instead of a process that serves an empty zone for the whole network and reports
    itself healthy while doing it.
    """
    monkeypatch.setenv("PROXMOX_HOSTS", "[]")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_incomplete_host_entry_fails(monkeypatch):
    """A host missing its token is a configuration error, not a host to skip."""
    monkeypatch.setenv("PROXMOX_HOSTS", json.dumps([{"host": "pve1.example", "user": "dns@pve"}]))
    with pytest.raises(ValidationError):
        Settings(_env_file=None)
