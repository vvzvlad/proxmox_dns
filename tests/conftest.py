import os

# Provide the required Proxmox credentials BEFORE any test imports src.settings
# (Settings() is built at import time and would otherwise fail). CI injects the
# same variables via the workflow's `env:` block.
os.environ.setdefault("PROXMOX_HOST", "test-host")
os.environ.setdefault("PROXMOX_USER", "test-user")
os.environ.setdefault("PROXMOX_PASSWORD", "test-pass")
