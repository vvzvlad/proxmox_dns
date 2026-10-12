import os

# Required Proxmox configuration, set before any test imports src.settings (Settings() is
# built at import time). Two entries so single-host-only code shows up. CI passes the same
# variable via the workflow's docker `-e` flags.
os.environ.setdefault(
    "PROXMOX_HOSTS",
    '[{"host":"test-host-1","user":"test@pve","token_name":"dns","token_value":"test-token-1"},'
    ' {"host":"test-host-2","user":"test@pve","token_name":"dns","token_value":"test-token-2"}]')
