import requests
from proxmoxer import ProxmoxAPI
from proxmoxer.core import ResourceException
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from src.logging_setup import logger
from src.settings import settings

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def build_client() -> ProxmoxAPI:
    """Create a Proxmox API client from settings (credentials come from ENV)."""
    return ProxmoxAPI(
        settings.proxmox_host,
        user=settings.proxmox_user,
        password=settings.proxmox_password,
        verify_ssl=False,
        service="PVE",
    )


def get_vm_ip(proxmox, node, vm):
    domain = (vm["name"].split("-")[0] + "." + settings.domain_suffix).lower()
    def_ip_v4 = "0.0.0.0"
    def_ip_v6 = "::"
    try:
        # Run state already comes with the qemu list / cluster resources;
        # no extra status.current call needed.
        if vm.get("status") != "running":
            return {"domain": domain, "ipv4": def_ip_v4, "ipv6": def_ip_v6}

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
        return {"domain": domain, "ipv4": vm_ip_v4 or def_ip_v4, "ipv6": vm_ip_v6 or def_ip_v6}

    except ResourceException:
        return {"domain": domain, "ipv4": def_ip_v4, "ipv6": def_ip_v6}
    except Exception:
        return {"domain": domain, "ipv4": def_ip_v4, "ipv6": def_ip_v6}


def get_vm_inventory(proxmox):
    """Cheap cluster-wide VM inventory for change detection (single API call).

    Returns a frozenset of (vmid, name, node, status) tuples for all non-template
    QEMU guests, or None if the API is unreachable. Comparing two signatures tells
    us whether the VM set / their names / run state changed, without the expensive
    per-VM guest-agent calls that get_domains performs.
    """
    try:
        resources = proxmox.cluster.resources.get(type="vm")
    # Degrade any transient API failure (timeout, 5xx/596, SSL, connection) to None
    # so the 2s polling loop just skips this tick and keeps its state, instead of
    # letting the exception restart the updater thread.
    except (requests.exceptions.RequestException, ResourceException) as e:
        logger.error(f"[Proxmox] Failed to query cluster resources: {e}")
        return None

    signature = set()
    for res in resources:
        if res.get("type") != "qemu":
            continue
        if res.get("template", 0) == 1:
            continue
        signature.add((res.get("vmid"), res.get("name"), res.get("node"), res.get("status")))
    return frozenset(signature)


def get_domains(proxmox):
    domains = []
    try:
        nodes = proxmox.nodes.get()
    # Same broad guard as get_vm_inventory: a transient error returns None so the
    # caller keeps the previous list rather than crashing the updater thread.
    except (requests.exceptions.RequestException, ResourceException) as e:
        logger.error(f"[Proxmox] Failed to list nodes: {e}")
        return None

    for node in nodes:
        try:
            vms = proxmox.nodes(node["node"]).qemu.get()
            for vm in vms:
                if vm.get("template", 0) == 1:
                    continue
                vm_info = get_vm_ip(proxmox, node, vm)
                domains.append(vm_info)
                logger.debug(f"[Proxmox] Got IPv4 {vm_info['ipv4']} and IPv6 {vm_info['ipv6']} for domain {vm_info['domain']}")
        except Exception as e:
            logger.error(f"[Proxmox] Failed to retrieve VM list for node {node['node']}: {e}")
            continue

    return domains
