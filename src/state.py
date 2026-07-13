"""Shared runtime registry of resolved VM domains.

The Proxmox updater thread rewrites this list in place (clear + extend) and the
DNS and HTTP servers read from it. Access it as ``state.servers_list`` (attribute
lookup on this module) rather than importing the list object directly, so every
reader observes both in-place mutations and reassignments.
"""

servers_list: list[dict] = []
