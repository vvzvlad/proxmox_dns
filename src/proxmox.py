import time

import requests
from proxmoxer import ProxmoxAPI
from proxmoxer.core import ResourceException
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from src.logging_setup import logger
from src.settings import ProxmoxHost, settings

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# How long a throttled warning below stays quiet after it has fired for a host. Such a
# warning has to REPEAT rather than fire once — the fault stands for as long as the host
# is misconfigured, and, exactly as for the collision warnings in src/app.py, a line that
# scrolled past during the incident is no use to whoever looks later. But get_domains()
# runs on every full refresh, and update_dns_periodically() in src/app.py takes a cheap
# inventory reading every `detect_interval` (2 s) and then refreshes whenever the
# inventory CHANGED or `full_refresh_interval` (60 s) has elapsed — so the minute is a
# LOWER bound on how often this code runs, not an upper one, and a host whose guests keep
# changing reaches it every couple of seconds. A host that genuinely holds no QEMU guests
# is a legitimate configuration, so a line every few seconds forever is not information
# either. An hour is the compromise: still there whenever someone comes looking, still
# rare enough to read.
_WARNING_INTERVAL = 3600  # seconds

# (host, key) -> time.monotonic() when that host last drew that particular warning. Keyed
# on the PAIR because more than one warning is throttled through this dict and one of them
# must not silence the other, and because every host is a separate fault to diagnose: a
# key without the host in it would let the first host to warn hide every other host's
# outage for an hour.
#
# Each host normally polls on its own thread and touches only its own keys. The one
# exception is the startup window in initial_domains() (src/app.py): after the deadline a
# late fetch thread and that host's own updater can both be inside get_domains() for the
# same host. What that can produce is one duplicate line — the read and the write in
# _warn_once_an_hour() are separate operations, so both threads can pass the read before
# either has written — and that cost is accepted. Monotonic because this measures an
# elapsed interval, which an NTP step must not move.
_warned_at: dict[tuple[str, str], float] = {}


def _warn_once_an_hour(host, key, message):
    """Log `message` at WARNING, at most once per _WARNING_INTERVAL per (host, key).

    `key` names WHICH warning is being throttled, so the two long-lived
    misconfigurations reported from get_domains() do not share one timer. A timestamp
    rather than an "already warned" flag: a stale entry costs one interval of silence at
    worst, never every future warning for the life of the process.

    THE THROTTLE IS UNCONDITIONAL — nothing anywhere clears an entry early. Recovery used
    to, and that defeated the throttle outright: the condition that fires each of these
    warnings and the condition that would clear it are exact complements, so a host
    alternating between broken and healthy drew a line on EVERY transition and the
    interval never applied at all. What removing the reset costs is precisely what the
    paragraph above already accepts — a fault that clears and comes back inside the
    interval waits out the rest of it.
    """
    now = time.monotonic()
    last_warned = _warned_at.get((host, key))
    if last_warned is not None and now - last_warned < _WARNING_INTERVAL:
        return
    logger.warning(message)
    _warned_at[(host, key)] = now


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

    NOT PURE: the two misconfiguration warnings here are throttled per host, and the
    timestamps they are throttled on live in module state (`_warned_at`) that survives the
    call — so anything calling this in a loop or a test has to reckon with it.
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
        # A host that answers the node index with nothing at all. This is NOT the missing
        # token ACL, tempting as that reading is: /nodes is declared with
        # `permissions => { user => 'all' }` in PVE and is served unfiltered, so even a
        # token carrying no ACL whatsoever gets the full node list back (measured on PVE
        # 9.2.10 with a fresh privsep token and no acl modify on it). A running PVE always
        # lists at least itself, so an empty index means the endpoint answered for
        # something that is not a healthy PVE. Nothing raised, so this line is the only
        # symptom there is; the missing-ACL case is caught after the loop instead.
        #
        # Throttled like the missing-ACL warning below, and for the same reason: an
        # address that does not point at a PVE is a configuration mistake that stands
        # until someone fixes it, so the line would otherwise repeat on every full
        # refresh — as often as every couple of seconds — for the life of the process.
        # It is NOT a transient state to wait out either — a restarting pveproxy gives a
        # connection error and a restarting pvedaemon a 5xx, both of which the except
        # above turns into an ERROR and a None return, so such a host never reaches this
        # branch at all. Nothing re-arms the throttle when nodes come back: see
        # _warn_once_an_hour() for why that reset was removed rather than kept.
        #
        # AND THIS BRANCH DOES NOT RETURN. An empty answer is still published, and it is
        # the one case here that is not treated as a failure: a host that genuinely has
        # no VMs is a legitimate configuration, and keeping its last records forever
        # would mean answering with addresses of guests that no longer exist — a worse
        # failure than a loud log line. The API answered; it just answered "nothing".
        # That is different from the None return in this function, which means it did
        # not answer at all. So the walk below simply iterates over an empty node list
        # and the empty slice falls out of `return domains` at the end.
        _warn_once_an_hour(
            host, "no-nodes",
            f"[Proxmox] {host}: the API returned NO nodes. A running PVE always lists at least "
            "itself, so this host answered the node index empty without failing — check that the "
            "address really points at a PVE host.")

    # Guests the listings HANDED BACK, counted before the template filter below, because
    # the warning after the loop is about whether the API showed us any guests at all.
    # `domains` cannot stand in for it: a host whose every QEMU guest is a template
    # produces an empty slice legitimately, and diagnosing that as a missing token ACL
    # sends whoever reads the log off after a permission problem that is not there.
    guests_listed = 0
    # How many nodes' guest listings came back without raising, and WHICH nodes raised.
    # Per node rather than one host-level "something failed" flag, because the two say
    # different things: a node that never answered explains nothing about the nodes that
    # DID answer, and it is only their answers that can carry the empty-permission-filter
    # signature. The names are kept, not just the count, so the warning below can say
    # whose guests are unaccounted for.
    nodes_answered = 0
    failed_nodes = []

    for node in nodes:
        try:
            vms = proxmox.nodes(node["node"]).qemu.get()
            guests_listed += len(vms)
            # COUNTED AFTER the len() above, deliberately. "Answered" has to mean "handed
            # back an ENUMERABLE listing", because an empty permission filter is the only
            # thing the diagnosis below can read out of it. proxmoxer returns the
            # endpoint's `data` as-is, so a malformed answer — `{"data": null}` — arrives
            # as None and only breaks at len(); counting the node as answered first would
            # put it in BOTH tallies at once and, on a single-node host, fire the ACL
            # diagnosis for a node that produced no listing at all.
            nodes_answered += 1
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
            failed_nodes.append(node["node"])
            logger.error(f"[Proxmox] {host}: failed to retrieve VM list for node {node['node']}: {e}")
            continue

    if nodes_answered and not guests_listed:
        # THE NASTIEST FAILURE THIS SERVICE HAS, because nothing errors anywhere. An API
        # token defaults to privilege separation (privsep=1) and its effective permissions
        # stay empty until it is given an ACL of its own — but such a token authenticates
        # perfectly, and the node index is served without any permission filtering at all,
        # so the setup LOOKS healthy from every angle the service reaches first. What
        # actually goes empty are the permission-filtered listings:
        # nodes/<node>/qemu and cluster/resources both hand back []. A node that ANSWERED
        # and showed no guests is the signature of exactly that, and the only place the
        # service can name it.
        unanswered = ""
        diagnosis = "If it does have VMs, the cause is almost certainly the API token"
        if failed_nodes:
            # THE WARNING STILL FIRES WITH A NODE DOWN, and the clause is what makes that
            # safe rather than a compromise with it. Suppressing the whole diagnosis on a
            # host-level "some node failed" flag is what this replaced: a cluster with one
            # permanently offline node could then never be diagnosed again, however broken
            # its token was, and that silence is exactly what hid it for as long as the
            # node stayed down. The hourly throttle above makes the extra line cheap, so
            # the failed nodes are NAMED instead — whoever reads the log needs to know
            # their guests are unaccounted for before going after a permission problem.
            #
            # It goes BEFORE the diagnosis, and the diagnosis is hedged while it is there.
            # A line that opens "almost certainly the API token" and only takes it back at
            # the end has already sent the reader after permissions; the caveat has to
            # arrive before the claim it qualifies, not after it.
            #
            # Singular and plural are both written out: the single-node case is the common
            # one, and "whether they hold guests" is simply wrong for it.
            if len(failed_nodes) == 1:
                unanswered = (
                    f" Note that {failed_nodes[0]} did not answer at all (see the ERROR above), "
                    "so whether it holds guests is unknown: if the missing names live there, "
                    "this is that failure and not a permission one.")
            else:
                unanswered = (
                    f" Note that {', '.join(failed_nodes)} did not answer at all (see the ERROR "
                    "above), so whether they hold guests is unknown: if the missing names live "
                    "there, this is that failure and not a permission one.")
            diagnosis = "Among the nodes that DID answer, the likeliest cause is the API token"
        message = (
            f"[Proxmox] {host}: nodes are listed but NOT ONE guest came back from any of them, "
            f"so this host contributes no names at all.{unanswered} {diagnosis}: with privilege "
            "separation (the default) a token whose own ACL is missing still authenticates and "
            "still sees the nodes, while every guest listing answers empty. Grant it one: "
            "pveum acl modify /vms -token 'user@pve!name' -role ProxmoxDNS. "
            "If this host runs only LXC containers, or holds no QEMU guests at all — a fresh "
            "install, or one temporarily emptied — the line is expected and there is nothing to "
            "fix: the service reads QEMU guests only and does not serve containers.")
        # Not re-armed when guests come back, either: see _warn_once_an_hour(). The reset
        # that used to live here and the condition just above are exact complements, so a
        # host flapping between "guests visible" and "no guests visible" cleared the
        # timestamp on every recovery and drew a fresh line on every relapse — the
        # throttle never got to apply.
        _warn_once_an_hour(host, "no-guests", message)

    return domains
