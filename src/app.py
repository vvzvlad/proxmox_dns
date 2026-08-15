import logging
import threading
import time

from src import state
from src.dns_server import start_dns_server
from src.http_server import start_http_server
from src.logging_setup import logger
from src.proxmox import build_client, get_domains, get_vm_inventory

# The Proxmox client is built lazily by ensure_client() and shared with the updater thread.
_proxmox = None
_client_error_logged = False


def ensure_client():
    """Return the shared Proxmox client, building it on the first attempt that succeeds.

    ProxmoxAPI authenticates EAGERLY inside its constructor (proxmoxer posts to
    /access/ticket), so an unreachable or rejecting PVE raises right here rather
    than later, on first use. Serving the zone must not depend on that: this
    process answers DNS for the whole internal network, and a PVE that is down
    when the container starts would otherwise kill it before the DNS and HTTP
    servers ever bind — with `restart: unless-stopped` that is a crash loop, and
    the outage becomes total instead of partial.

    Returning None instead lets the servers come up and answer from whatever the
    list currently holds (empty right after start), and the updater thread
    retries on its next tick.
    """
    global _proxmox, _client_error_logged
    if _proxmox is not None:
        return _proxmox
    try:
        _proxmox = build_client()
    except Exception as e:
        # Log the FIRST failure only: the updater retries every couple of seconds,
        # so logging each one would bury the rest of the log during an outage.
        if not _client_error_logged:
            logger.error(f"[Proxmox] Cannot build the API client, will keep retrying: {e}")
            _client_error_logged = True
        return None
    if _client_error_logged:
        logger.warning("[Proxmox] API client built after earlier failures")
        _client_error_logged = False
    return _proxmox


def update_dns_periodically():
    detect_interval = 2          # seconds between cheap inventory checks
    full_refresh_interval = 60   # seconds between unconditional full refreshes
    last_signature = None
    last_full_refresh = 0.0

    while True:
        time.sleep(detect_interval)

        proxmox = ensure_client()
        if proxmox is None:
            # No usable client yet (PVE down / credentials rejected): keep the
            # previous list and try to build one again on the next tick.
            continue

        signature = get_vm_inventory(proxmox)
        if signature is None:
            # API unreachable: keep the previous list, retry on the next tick.
            continue

        changed = signature != last_signature
        due_for_full = time.time() - last_full_refresh >= full_refresh_interval
        if not (changed or due_for_full):
            continue

        domains = get_domains(proxmox)
        if domains is None:
            logger.warning("[Proxmox] Failed to update DNS servers list, kept previous list")
            continue

        state.servers_list.clear()
        state.servers_list.extend(domains)
        last_full_refresh = time.time()

        # Log only on a real inventory change; the periodic refresh stays quiet.
        # Skip the log on the very first refresh (last_signature is None at startup).
        if changed and last_signature is not None:
            logger.info(f"[Proxmox] VM inventory changed, refreshed {len(domains)} domains")
        last_signature = signature


def initial_domains():
    """Best-effort first fill of the zone, before the servers are running.

    Everything that can fail on the Proxmox side at startup is contained here,
    because this runs BEFORE the DNS and HTTP threads exist: an exception
    escaping this function stops the process from ever serving the zone.

    get_domains() already degrades an unreachable API to None, but only for the
    two exception types it knows about. proxmoxer's AuthenticationError derives
    from plain Exception — it is neither a requests RequestException nor a
    ResourceException — so it goes straight through that guard. Inside the
    updater thread start_thread() would catch it; here there is nothing above us
    yet, which is exactly why the net is cast wide.
    """
    proxmox = ensure_client()
    if proxmox is None:
        return None
    try:
        return get_domains(proxmox)
    except Exception as e:
        logger.error(f"[Proxmox] Initial domain fetch failed, starting with an empty zone: {e}")
        return None


def run():
    # Both the client and the first fetch are allowed to come back empty when PVE
    # is unreachable — see ensure_client() and initial_domains(). The servers
    # below start either way, so the zone is served (empty at first) while the
    # updater thread keeps retrying the connection.
    initial = initial_domains()
    if initial:
        state.servers_list.extend(initial)

    def start_thread(target):
        while True:
            try:
                target()
            except Exception as e:
                logger.error(f"[Thread] Error in {target.__name__}: {e}")
                time.sleep(1)

    threading.Thread(target=lambda: start_thread(update_dns_periodically), daemon=True).start()
    threading.Thread(target=lambda: start_thread(start_dns_server), daemon=True).start()
    threading.Thread(target=lambda: start_thread(start_http_server), daemon=True).start()

    logger.log(logging.CRITICAL, "ProxDNS server started")

    while True:
        time.sleep(30)
        if not state.servers_list:  # nothing yet; avoid max() on an empty list
            continue
        max_domain_length = max(len(server["domain"]) for server in state.servers_list)
        max_ipv4_length = max(len(server.get("ipv4", "")) for server in state.servers_list)
        max_ipv6_length = max(len(server.get("ipv6", "")) for server in state.servers_list)
        for server in state.servers_list:
            domain = server["domain"].ljust(max_domain_length)
            ipv4_address = server.get("ipv4", "--.--.--.--").ljust(max_ipv4_length)
            ipv6_address = server.get("ipv6", "--").ljust(max_ipv6_length)
            logger.debug(f"{domain}\t{ipv4_address}\t{ipv6_address}")
