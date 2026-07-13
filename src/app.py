import logging
import threading
import time

from src import state
from src.dns_server import start_dns_server
from src.http_server import start_http_server
from src.logging_setup import logger
from src.proxmox import build_client, get_domains

# The Proxmox client is created once in run() and shared with the updater thread.
_proxmox = None


def update_dns_periodically():
    sleep_low = 1
    sleep_max = 5
    sleep_delay = sleep_max
    previous_count = 0
    last_change_time = None

    while True:
        time.sleep(sleep_delay)
        domains = get_domains(_proxmox)
        if domains is None:
            logger.warning("[Proxmox] Failed to update DNS servers list, left previous list")
            continue
        state.servers_list.clear()
        state.servers_list.extend(domains)
        logger.info(f"[Proxmox] Updated DNS servers list with {len(domains)} servers(period {sleep_delay})")

        if len(domains) != previous_count:
            last_change_time = time.time()
        previous_count = len(domains)

        if last_change_time and time.time() - last_change_time < 60:
            sleep_delay = sleep_max
        else:
            sleep_delay = sleep_low


def run():
    global _proxmox
    _proxmox = build_client()

    initial = get_domains(_proxmox)
    if initial:  # guard against None (API unreachable) at startup
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
