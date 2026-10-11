import requests
from proxmoxer import ProxmoxAPI
from proxmoxer.core import ResourceException
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from src.logging_setup import logger
from src.settings import ProxmoxHost, settings

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def build_client(cfg: ProxmoxHost) -> ProxmoxAPI:
    """Create a Proxmox API client for ONE host (credentials come from ENV).

    API token auth, and that is not merely a credential choice: proxmoxer builds
    the token header per request and performs NO network call here, whereas the
    password path posts to /access/ticket from inside the constructor. See
    ensure_client() in src/app.py for what that moves.
    """
    return ProxmoxAPI(
        cfg.host,
        user=cfg.user,
        token_name=cfg.token_name,
        token_value=cfg.token_value,
        verify_ssl=False,
        service="PVE",
    )


def get_vm_ip(proxmox, node, vm, host):
    domain = (vm["name"].split("-")[0] + "." + settings.domain_suffix).lower()
    def_ip_v4 = "0.0.0.0"
    def_ip_v6 = "::"
    # Provenance for the merge in src/app.py: which PVE endpoint this entry came from,
    # which guest it is, and whether that guest is up — the merge ranks a collision
    # between two hosts on exactly those. EVERY return path below carries them, the
    # failure ones included: an entry missing `status` cannot be ranked as running and
    # would lose a collision it should have won.
    origin = {"host": host, "vmid": vm.get("vmid"), "status": vm.get("status")}
    try:
        # Run state already comes with the qemu list / cluster resources;
        # no extra status.current call needed.
        if vm.get("status") != "running":
            return {"domain": domain, "ipv4": def_ip_v4, "ipv6": def_ip_v6, **origin}

        network_status = proxmox.nodes(node["node"]).qemu(vm["vmid"]).agent("network-get-interfaces").get()
        vm_ip_v4 = None
        vm_ip_v6 = None

        if "result" in network_status:
            for interface in network_status["result"]:
                if interface["name"].startswith(("lo", "br-", "veth", "docker", "wg", "tun")):
                    continue
                if "hardware-address" in interface and interface["hardware-address"] == "00:00:00:00:00:00":
                    continue
                for ip in interface.get("ip-addresses", []):
                    if ip["ip-address-type"] == "ipv4" and not vm_ip_v4:
                        vm_ip_v4 = ip["ip-address"]
                    elif ip["ip-address-type"] == "ipv6" and not vm_ip_v6:
                        vm_ip_v6 = ip["ip-address"]
                if vm_ip_v4 and vm_ip_v6:
                    break
        return {"domain": domain, "ipv4": vm_ip_v4 or def_ip_v4, "ipv6": vm_ip_v6 or def_ip_v6, **origin}

    except ResourceException:
        return {"domain": domain, "ipv4": def_ip_v4, "ipv6": def_ip_v6, **origin}
    except Exception:
        return {"domain": domain, "ipv4": def_ip_v4, "ipv6": def_ip_v6, **origin}


def get_vm_inventory(proxmox, host):
    """Cheap host-wide VM inventory for change detection (single API call).

    Returns a frozenset of (vmid, name, node, status) tuples for all non-template
    QEMU guests, or None if the API is unreachable. Comparing two signatures tells
    us whether the VM set / their names / run state changed, without the expensive
    per-VM guest-agent calls that get_domains performs.

    `host` is only for the log line, but it is not decoration: every host polls on
    its own thread, so an unattributed failure here says one of them is down
    without saying which.
    """
    try:
        resources = proxmox.cluster.resources.get(type="vm")
    # Degrade any transient API failure (timeout, 5xx/596, SSL, connection) to None
    # so the 2s polling loop just skips this tick and keeps its state, instead of
    # letting the exception restart the updater thread.
    except (requests.exceptions.RequestException, ResourceException) as e:
        logger.error(f"[Proxmox] {host}: failed to query cluster resources: {e}")
        return None

    signature = set()
    for res in resources:
        if res.get("type") != "qemu":
            continue
        if res.get("template", 0) == 1:
            continue
        signature.add((res.get("vmid"), res.get("name"), res.get("node"), res.get("status")))
    return frozenset(signature)


def get_domains(proxmox, host):
    """One host's whole slice of the zone, or None if the node listing itself failed.

    A node whose guest listing fails is logged and its guests are missing from the slice.
    """
    domains = []
    try:
        nodes = proxmox.nodes.get()
    # Same broad guard as get_vm_inventory: a transient error returns None so the
    # caller keeps the previous list rather than crashing the updater thread.
    except (requests.exceptions.RequestException, ResourceException) as e:
        logger.error(f"[Proxmox] {host}: failed to list nodes: {e}")
        return None

    for node in nodes:
        try:
            vms = proxmox.nodes(node["node"]).qemu.get()
            for vm in vms:
                if vm.get("template", 0) == 1:
                    continue
                vm_info = get_vm_ip(proxmox, node, vm, host)
                domains.append(vm_info)
                logger.debug(f"[Proxmox] {host}: got IPv4 {vm_info['ipv4']} and IPv6 {vm_info['ipv6']} for domain {vm_info['domain']}")
        except Exception as e:
            # The other nodes still contribute; this node's guests are missing from the slice.
            logger.error(f"[Proxmox] {host}: failed to retrieve VM list for node {node['node']}: {e}")
            continue

    return domains
