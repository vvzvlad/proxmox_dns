import os

import pytest

# Provide the required Proxmox configuration BEFORE any test imports src.settings
# (Settings() is built at import time and would otherwise fail). One JSON list, parsed
# by pydantic-settings into ProxmoxHost models; two entries rather than one so an
# import-time regression that only handles a single host shows up here. CI injects the
# same variable via the workflow's docker `-e` flags.
os.environ.setdefault(
    "PROXMOX_HOSTS",
    '[{"host":"test-host-1","user":"test@pve","token_name":"dns","token_value":"test-token-1"},'
    ' {"host":"test-host-2","user":"test@pve","token_name":"dns","token_value":"test-token-2"}]')


@pytest.fixture(autouse=True)
def _forget_hosts_already_warned():
    """Reset the per-(host, warning) throttle get_domains() keeps in module state.

    It records when a host last drew each of its throttled warnings, and that outlives a
    test: whichever test runs second would see the first one's host already stamped and
    silently stop asserting anything about the warning at all. Here rather than in
    tests/test_proxmox.py because the state is global — any test anywhere that reaches
    get_domains() leaks it into the next one.

    Imported inside the fixture: src.proxmox pulls in src.settings, which builds
    Settings() at import time and needs the environment above to exist first.
    """
    from src import proxmox

    proxmox._warned_at.clear()
    yield
    proxmox._warned_at.clear()
