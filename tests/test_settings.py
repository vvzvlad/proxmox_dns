import pytest
from pydantic import ValidationError

from src.settings import Settings


def test_loads_from_env(monkeypatch):
    monkeypatch.setenv("PROXMOX_HOST", "pve.example")
    monkeypatch.setenv("PROXMOX_USER", "dns@pve")
    monkeypatch.setenv("PROXMOX_PASSWORD", "secret")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("SUBDOMAINS", "true")
    s = Settings(_env_file=None)
    assert s.proxmox_host == "pve.example"
    assert s.proxmox_user == "dns@pve"
    assert s.proxmox_password == "secret"
    assert s.log_level == "DEBUG"
    assert s.subdomains is True


def test_defaults(monkeypatch):
    monkeypatch.setenv("PROXMOX_HOST", "h")
    monkeypatch.setenv("PROXMOX_USER", "u")
    monkeypatch.setenv("PROXMOX_PASSWORD", "p")
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    monkeypatch.delenv("SUBDOMAINS", raising=False)
    monkeypatch.delenv("DOMAIN_SUFFIX", raising=False)
    s = Settings(_env_file=None)
    assert s.log_level == "INFO"
    assert s.subdomains is False
    assert s.domain_suffix == "lc"


def test_missing_credential_fails(monkeypatch):
    monkeypatch.delenv("PROXMOX_HOST", raising=False)
    monkeypatch.delenv("PROXMOX_USER", raising=False)
    monkeypatch.delenv("PROXMOX_PASSWORD", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)
