from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from src.config_errors import load_settings_or_exit


class ProxmoxHost(BaseModel):
    """One STANDALONE PVE endpoint and the API token used to read it.

    Independent hosts, not nodes of a cluster: a cluster is already covered by a
    single entry, because `nodes.get()` and `cluster.resources.get()` are
    cluster-wide. Each entry therefore carries its own address AND its own token.

    Token auth only — no password field. proxmoxer builds the ticket for password
    auth inside the constructor (a network call, renewed every hour), while a
    token is only a header assembled per request; proxmoxer's own advice is to
    prefer tokens for anything that calls less often than the ticket lifetime.
    """

    host: str
    user: str
    token_name: str
    token_value: str


class Settings(BaseSettings):
    # Proxmox API access — one entry per independent PVE host, merged into one zone.
    # Secrets / deployment-specific addresses, so NO defaults: a missing variable
    # makes Settings() fail at startup with a clear message. pydantic-settings parses
    # the JSON in PROXMOX_HOSTS into these models by itself; see .env.example for the
    # shape. min_length=1 for the same reason there are no defaults — a configuration
    # with zero hosts must fail at startup rather than quietly serve an empty zone.
    proxmox_hosts: list[ProxmoxHost] = Field(min_length=1)

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
