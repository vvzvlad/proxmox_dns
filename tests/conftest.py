import os

# Provide the required Proxmox configuration BEFORE any test imports src.settings
# (Settings() is built at import time and would otherwise fail). One JSON list, parsed
# by pydantic-settings into ProxmoxHost models; two entries rather than one so an
# import-time regression that only handles a single host shows up here. CI injects the
# same variable via the workflow's docker `-e` flags.
os.environ.setdefault(
    "PROXMOX_HOSTS",
    '[{"host":"test-host-1","user":"test@pve","token_name":"dns","token_value":"test-token-1"},'
    ' {"host":"test-host-2","user":"test@pve","token_name":"dns","token_value":"test-token-2"}]')
