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

    None is the caller's "keep the slice you already have" signal, and the node listing
    failing is what raises it. A single NODE of a cluster failing does not: its guests
    are simply missing from the returned list, which the caller cannot tell from a
    complete one, so it publishes it and that node's guests drop out of the zone until
    the node answers again.

    THAT IS BEHAVIOUR INHERITED FROM BEFORE MULTI-HOST SUPPORT and deliberately left
    alone here rather than endorsed. Two fixes were considered and declined for this
    change: carrying the failed node's previous entries over (the merge would then serve
    entries no refresh has confirmed for an unbounded time, and nothing decides when to
    let go of them), and returning None so the caller keeps its whole slice (that freezes
    the host's HEALTHY nodes too, for as long as a node is down — a node under
    maintenance is still listed by nodes.get() — and, because the caller only advances
    its refresh bookkeeping on a successful fetch, it also turns the once-a-minute full
    walk into one every couple of seconds, a guest-agent call per VM each time). Either
    is a change worth making on its own evidence, not as a side effect of adding hosts.
    """
    domains = []
    try:
        nodes = proxmox.nodes.get()
    # Same broad guard as get_vm_inventory: a transient error returns None so the
    # caller keeps the previous list rather than crashing the updater thread.
    except (requests.exceptions.RequestException, ResourceException) as e:
        logger.error(f"[Proxmox] {host}: failed to list nodes: {e}")
        return None

    if not nodes:
        # The nastiest failure this service has, because NOTHING errors. An API token
        # defaults to privilege separation (privsep=1), and until it is given an ACL of
        # its own its effective permissions are empty — so it authenticates perfectly
        # and every listing endpoint answers with an empty list. Without this line the
        # only symptom is a zone that quietly loses this host's names.
        logger.warning(
            f"[Proxmox] {host}: the API returned NO nodes. If the host does have nodes, the most "
            "likely cause is the API token: with privilege separation (the default) a token whose "
            "own ACL is missing authenticates fine and gets empty lists back from every listing "
            "endpoint. Grant it one: pveum acl modify /vms -token 'user@pve!name' -role ProxmoxDNS")
        # AN EMPTY ANSWER IS STILL PUBLISHED, and it is the one case here that is not
        # treated as a failure: a host that genuinely has no VMs is a legitimate
        # configuration, and keeping its last records forever would mean answering with
        # addresses of guests that no longer exist — a worse failure than a loud log
        # line. The API answered; it just answered "nothing". That is different from
        # the None return in this function, which means it did not answer at all.

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
            # The other nodes still contribute, and the list goes back short by this
            # node's guests. The caller cannot tell that from a complete answer, so it
            # publishes it and this node's names leave the zone until it recovers —
            # see the docstring for why that is being left as it was found. The ERROR
            # is the only signal it happened, and it is logged on every refresh.
            logger.error(f"[Proxmox] {host}: failed to retrieve VM list for node {node['node']}: {e}")
            continue

    return domains
