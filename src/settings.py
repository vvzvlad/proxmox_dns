from pydantic_settings import BaseSettings, SettingsConfigDict

from src.config_errors import load_settings_or_exit


class Settings(BaseSettings):
    # Proxmox API access — the credentials and host of our OWN PVE cluster.
    # Secrets / deployment-specific addresses, so NO defaults: a missing variable
    # makes Settings() fail at startup with a clear message.
    proxmox_host: str
    proxmox_user: str
    proxmox_password: str

    # Non-secret configuration below — sensible defaults are allowed.

    # Logging verbosity: DEBUG / INFO / WARNING / ERROR / CRITICAL.
    log_level: str = "INFO"

    # When true, subdomains of a VM domain resolve to the parent's IP
    # (e.g. sub.foo.lc -> foo.lc's address).
    subdomains: bool = False

    # Suffix appended to the VM name prefix to build the FQDN
    # (VM name "foo-bar" -> "foo.<domain_suffix>").
    domain_suffix: str = "lc"

    # Ports the servers listen on inside the container.
    dns_port: int = 53
    http_port: int = 80

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


# Build settings with a clear startup error (naming the missing/invalid env var)
# instead of a raw pydantic traceback.
settings = load_settings_or_exit(Settings)
