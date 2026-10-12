import logging
import signal
import threading
import time

from src import state
from src.dns_server import start_dns_server
from src.http_server import start_http_server
from src.logging_setup import logger
from src.proxmox import build_client, get_domains, get_vm_inventory
from src.settings import settings


class HostState:
    """Everything ONE PVE host owns: its config, its client, and its slice of the zone.

    Nothing is shared between hosts, including `domains`, the host's last-known-good answer:
    a host that stops answering keeps the records it last published.
    """

    def __init__(self, cfg):
        self.cfg = cfg
        self.client = None
        self.client_error_logged = False
        self.last_signature = None
        self.last_full_refresh = 0.0
        self.domains = []
        # Whether anything has filled `domains` for this host. Read and written only under
        # _publish_lock; lets a late startup fetch publish without overwriting the updater's
        # newer slice (see initial_domains()).
        self.has_published = False


# One entry per configured host, in PROXMOX_HOSTS order — which is also the order the
# merge breaks ties in, so the operator controls it by ordering the config.
_hosts = [HostState(cfg) for cfg in settings.proxmox_hosts]

# Held while a host swaps its own slice and the merged list is rebuilt from all of them.
# Several host threads publish concurrently, and each one reads every OTHER host's slice
# to do it.
_publish_lock = threading.Lock()

# Set by request_shutdown() when a stop signal arrives. The main loop waits on it instead of
# sleeping, so a stop is answered at once.
_shutdown = threading.Event()
# Which signal asked for the shutdown. Logged after the loop rather than from the handler, which
# runs between two bytecodes of the main thread and should touch as little as possible.
_shutdown_signal = None

# Seconds between the zone dumps the main loop logs.
REPORT_INTERVAL = 30

# How long run() waits for the startup fetch of all hosts before binding the sockets without the
# ones that have not answered. Hosts are fetched concurrently, so this only caps a black-holing host.
# 10 s: above proxmoxer's 5 s per-request timeout so a merely slow host still makes the pre-fill,
# and a small fraction of the 45 s `stop_grace_period` in docker-compose.yml. A host that misses it
# loses only the pre-fill; its updater publishes as soon as it answers.
INITIAL_FETCH_DEADLINE = 10
# How often the wait above re-checks the fetches. The wait is on the shutdown Event, so a stop
# returns at once; this only bounds how long a completed fetch waits to be harvested.
INITIAL_FETCH_POLL = 0.1


def ensure_client(host):
    """Return one host's Proxmox client, building it on the first attempt that succeeds.

    With API token auth the constructor makes no network call (proxmoxer builds a
    `PVEAPIToken=...` header per request), so this guards configuration failures; an
    unreachable host surfaces on the first real request.

    Invariant: nothing on the way to the DNS and HTTP threads may depend on Proxmox
    succeeding. A PVE that is down at container start must not kill the process before
    the servers bind, or `restart: always` turns it into a crash loop with the zone
    unresolvable.

    Returning None lets the servers come up and answer from whatever the list holds
    (empty right after start); this host's updater thread retries on its next tick.
    """
    if host.client is not None:
        return host.client
    try:
        host.client = build_client(host.cfg)
    except Exception as e:
        # Log the FIRST failure only: the updater retries every couple of seconds,
        # so logging each one would bury the rest of the log during an outage.
        if not host.client_error_logged:
            logger.error(
                f"[Proxmox] {host.cfg.host}: cannot build the API client, will keep retrying: {e}")
            host.client_error_logged = True
        return None
    if host.client_error_logged:
        logger.warning(f"[Proxmox] {host.cfg.host}: API client built after earlier failures")
        host.client_error_logged = False
    return host.client


def _rank(entry):
    """How good a candidate for a domain is, LOWEST wins. See merge_domains()."""
    if entry.get("status") != "running":
        return 2
    # The sentinels src/proxmox.py stores for a guest it could not read an address
    # from; dns_server.py depends on them being these exact values.
    if entry.get("ipv4", "0.0.0.0") != "0.0.0.0" or entry.get("ipv6", "::") != "::":
        return 0
    return 1


def _describe_claim(entries):
    """`host` and every guest it is claiming one name with — the actionable half of a warning."""
    guests = ", ".join(f"vmid {entry.get('vmid')} ({entry.get('status')})" for entry in entries)
    return f"{entries[0].get('host')} {guests}"


def _warn_about_addresses_two_hosts_share(merged):
    """WARN when one address reaches the zone from two different hosts.

    Independent PVE hosts may run overlapping RFC1918 ranges, so two guests with
    different names can legitimately share an address; both A records are right and
    the merge must not pick one. But src/dns_server.py answers a PTR with the first
    entry carrying the address, so one name is unreachable in reverse, depending on
    list order. Logged on every rebuild, like the collision warning in merge_domains().
    """
    # The sentinels src/proxmox.py stores for a guest with no readable address; every
    # stopped guest carries them, so they are not conflicts.
    for field, sentinel in (("ipv4", "0.0.0.0"), ("ipv6", "::")):
        by_address = {}
        for entry in merged:
            address = entry.get(field)
            if not address or address == sentinel:
                continue
            by_address.setdefault(address, []).append(entry)
        for address, entries in by_address.items():
            if len({entry.get("host") for entry in entries}) < 2:
                # One host reusing an address is not a product of merging hosts.
                continue
            claims = "; ".join(
                f"{entry.get('domain')} on {entry.get('host')} (vmid {entry.get('vmid')})"
                for entry in entries)
            logger.warning(
                f"[Proxmox] {field} {address} is claimed by guests on several hosts: {claims}. "
                "Both A records are served, but a PTR query for that address can only be "
                "answered with one of these names, and which one is arbitrary")


def merge_domains(per_host_lists):
    """Merge the per-host slices into one zone. Between hosts, THE RUNNING VM WINS.

    `per_host_lists` arrives in PROXMOX_HOSTS order, which is the tie-break: among
    equally good candidates the earliest host keeps the name.

    Entries are grouped by host first. The domain is the VM name's first segment, so
    `web-01` and `web-02` on one host both produce `web.lc`; a host that is the only
    claimant of a name passes all its entries through, since dropping one would also
    drop its PTR answer (src/dns_server.py answers PTR only for addresses in the list).

    Between hosts, each host is ranked by its best entry (see _rank()): running with a
    real address; running with only the sentinels (agent missing); anything else. The
    winning host contributes all its entries for that name.

    Within a name, entries are emitted best first: src/dns_server.py answers an A query
    with the first matching entry, so a stopped guest listed first would resolve to the
    0.0.0.0 sentinel. sorted() is stable and nothing is dropped.

    A cross-host collision is logged at WARNING on every rebuild (it lasts as long as
    the misconfiguration does); a duplicate within one host is DEBUG.
    """
    # domain -> {host index -> that host's entries for it}. Both dicts keep insertion
    # order, so the hosts under a domain are in PROXMOX_HOSTS order and the entries
    # under a host are in the order that host reported them.
    grouped = {}
    for host_index, entries in enumerate(per_host_lists):
        for entry in entries:
            grouped.setdefault(entry.get("domain"), {}).setdefault(host_index, []).append(entry)

    merged = []
    for domain, by_host in grouped.items():
        if len(by_host) == 1:
            (entries,) = by_host.values()
            if len(entries) > 1:
                logger.debug(
                    f"[Proxmox] {domain} is claimed by {len(entries)} guests on one host: "
                    f"{_describe_claim(entries)}. All of them stay in the zone, as they did "
                    "before the zone was assembled from several hosts")
            # Best first: the DNS server answers with the first match (see the docstring).
            merged.extend(sorted(entries, key=_rank))
            continue

        # Rank every host by its best entry; min() keeps the earliest of equal-ranked
        # hosts, which makes PROXMOX_HOSTS order the tie-break.
        winner_index = min(by_host, key=lambda index: min(_rank(e) for e in by_host[index]))
        for host_index, entries in by_host.items():
            if host_index == winner_index:
                continue
            logger.warning(
                f"[Proxmox] Domain collision on {domain}: {_describe_claim(entries)} loses to "
                f"{_describe_claim(by_host[winner_index])}")
        # Best first, as above: the collision decides the host, this decides which of its
        # entries the DNS server answers with.
        merged.extend(sorted(by_host[winner_index], key=_rank))

    _warn_about_addresses_two_hosts_share(merged)
    return merged


def _publish_locked(host, domains):
    """Swap one slice and rebuild the zone. THE CALLER MUST HOLD _publish_lock.

    Rebinds state.servers_list rather than clearing and extending it: clear() + extend()
    leaves a window in which a DNS query sees an empty list and answers NXDOMAIN, which
    the asker caches. src/state.py is read through attribute lookup so the rebind is seen.
    """
    host.domains = domains
    host.has_published = True
    state.servers_list = merge_domains([h.domains for h in _hosts])


def publish_domains(host, domains):
    """Store one host's fresh slice and rebuild the zone from all of the slices."""
    with _publish_lock:
        _publish_locked(host, domains)


def update_dns_periodically(host):
    """Poll ONE host forever. run() gives every host its own thread.

    Per host because get_domains() makes a guest-agent call per VM at a 5 s timeout,
    so one black-holing host in a shared loop would hold every other host's refresh.
    """
    detect_interval = 2          # seconds between cheap inventory checks
    full_refresh_interval = 60   # seconds between unconditional full refreshes

    while True:
        time.sleep(detect_interval)

        proxmox = ensure_client(host)
        if proxmox is None:
            # No usable client yet: keep this host's previous slice and try to build
            # one again on the next tick.
            continue

        signature = get_vm_inventory(proxmox, host.cfg.host)
        if signature is None:
            # API unreachable: keep this host's slice, retry on the next tick. The
            # other hosts' slices are untouched — they are not on this thread.
            continue

        changed = signature != host.last_signature
        due_for_full = time.time() - host.last_full_refresh >= full_refresh_interval
        if not (changed or due_for_full):
            continue

        domains = get_domains(proxmox, host.cfg.host)
        if domains is None:
            logger.warning(
                f"[Proxmox] {host.cfg.host}: failed to update the DNS servers list, "
                "kept the previous one")
            continue

        publish_domains(host, domains)
        host.last_full_refresh = time.time()

        # Log only on a real inventory change; the periodic refresh stays quiet.
        # Skip the log on the very first refresh (last_signature is None at startup).
        if changed and host.last_signature is not None:
            logger.info(
                f"[Proxmox] {host.cfg.host}: VM inventory changed, refreshed {len(domains)} domains")
        host.last_signature = signature


def _updater_for(host):
    """Bind one host to the updater loop, for the zero-argument target start_thread() wants.

    A bare lambda would report every host's crash as `Error in <lambda>`; the name
    says which host died.
    """
    def run_updater():
        update_dns_periodically(host)

    run_updater.__name__ = f"update_dns_periodically({host.cfg.host})"
    return run_updater


def _initial_fetch(host):
    """One host's startup fetch. Returns its slice, or None if it could not be read.

    Runs before the DNS and HTTP threads exist, so nothing may escape it. get_domains()
    degrades only requests and proxmoxer ResourceException errors to None; proxmoxer's
    AuthenticationError derives from plain Exception, hence the wide net.
    """
    proxmox = ensure_client(host)
    if proxmox is None:
        return None
    try:
        domains = get_domains(proxmox, host.cfg.host)
    except Exception as e:
        logger.error(
            f"[Proxmox] {host.cfg.host}: initial domain fetch failed, "
            f"starting without its names: {e}")
        return None
    # A token without its own ACL sees the nodes but gets no guests, and nothing raises.
    if domains == []:
        logger.error(
            f"[Proxmox] {host.cfg.host}: no QEMU guests visible at startup; if the host has "
            "VMs, its API token lacks the ACL (make pve-setup)")
    return domains


def initial_domains():
    """Best-effort first fill of the zone across ALL hosts, before the servers are running.

    The fetches run concurrently, one short-lived thread per host: the zone is not served
    yet, so the wait here is downtime, and it is one slow host's latency capped by
    INITIAL_FETCH_DEADLINE rather than the sum. A host that misses the deadline does not
    hold the servers back; its answer is published when it arrives, from its fetch
    thread if nothing newer exists, otherwise by its updater.

    The pre-fill must stay: without it the DNS server answers NXDOMAIN for real names
    until the first poll (the updater sleeps `detect_interval` first), and negative
    answers are cached. Not-yet-bound is better than authoritative-and-wrong.

    The wait is abandoned when the shutdown flag is set, so a SIGTERM during startup does
    not spend the grace period here.

    Publishes and returns nothing: a late fetch publishes from its own thread, and a
    caller's assignment afterwards would overwrite it with the pre-deadline merge.
    """
    # Results go into slots so that "on time" is decided in one place. The harvest below
    # sets `harvested` and reads the slots in one critical section under _publish_lock; a
    # fetch that finds it set publishes its own answer instead. No answer can be neither
    # harvested nor published.
    #
    # `pending` is distinct from None: None means the fetch ran and failed (already
    # logged); only `pending` hosts are named in the deadline warning.
    pending = object()
    slots = [pending] * len(_hosts)
    done = [threading.Event() for _ in _hosts]
    harvested = False

    def fetch(index, host):
        try:
            domains = _initial_fetch(host)
            # A late answer is published only while nothing else has filled this host's
            # slice: a slow host should not wait for a whole updater cycle, but a stale
            # pre-bind answer must never overwrite the updater's (`has_published` under
            # the lock).
            with _publish_lock:
                on_time = not harvested
                if on_time:
                    slots[index] = domains
                late_publish = (
                    not on_time and domains is not None and not host.has_published)
                if late_publish:
                    _publish_locked(host, domains)
            if late_publish:
                logger.info(
                    f"[Proxmox] {host.cfg.host}: answered after the "
                    f"{INITIAL_FETCH_DEADLINE} s startup deadline; its names went into "
                    "the zone now rather than at its updater's first successful poll")
        finally:
            done[index].set()

    for index, host in enumerate(_hosts):
        threading.Thread(
            target=fetch, args=(index, host), daemon=True,
            name=f"initial-fetch({host.cfg.host})").start()

    deadline = time.monotonic() + INITIAL_FETCH_DEADLINE
    while not all(event.is_set() for event in done):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        # Wait on the shutdown Event, so a stop mid-fetch returns at once. The fetch
        # threads are daemons and die with the interpreter.
        if _shutdown.wait(min(INITIAL_FETCH_POLL, remaining)):
            break

    # Closing the harvest and reading the slots are one step under the lock. A slot is
    # written only under this lock while `harvested` is false, so every filled slot is an
    # on-time answer, and any fetch not yet in a slot will find `harvested` set and either
    # publish its answer itself (unless the updater already published) or, on failure,
    # leave the slice as it is.
    #
    # `done[index]` must not be consulted here: it is set after the lock is released, so
    # a fetch that had filled its slot could be skipped and published by neither side.
    #
    # A late fetch thread can still run alongside its host's updater: both may build a
    # client via ensure_client() and share one proxmoxer requests.Session, which is not
    # documented as thread-safe. host.domains is only written under the lock.
    with _publish_lock:
        harvested = True
        late = []
        for index, host in enumerate(_hosts):
            domains = slots[index]
            if domains is pending:
                late.append(host.cfg.host)
                continue
            if domains is None:
                # It answered, and the answer was a failure _initial_fetch() has already
                # logged. Its slice stays as it was, and its updater retries.
                continue
            host.domains = domains
            # Bookkeeping, not a guard: keeps the HostState invariant the late branch
            # relies on.
            host.has_published = True
        state.servers_list = merge_domains([h.domains for h in _hosts])

    # Built from the slots rather than `done`, which lags the slot write (see above).
    if late and not _shutdown.is_set():
        logger.warning(
            f"[Proxmox] {', '.join(late)}: no answer within {INITIAL_FETCH_DEADLINE} s, starting "
            "without their names rather than holding the DNS server back; they publish as soon "
            "as they answer, either from the fetch itself or from their own updater thread")


def request_shutdown(signum, _frame):
    """Handler for SIGTERM and SIGINT: ask the main loop to return.

    Only records the signal and sets the Event; logging and the return out of run()
    happen on the main loop.

    Nothing needs flushing: the service is stateless, writes no files, and its log
    handler flushes per record. The daemon threads holding the sockets die with the
    interpreter.

    Event.set() is not async-signal-safe: a signal landing while the main thread holds the
    Event's internal lock inside wait() would deadlock this handler. The window is a few
    instructions per REPORT_INTERVAL, and setting an Event from a handler is the standard
    idiom; a self-pipe or set_wakeup_fd() is not worth the extra machinery.
    """
    global _shutdown_signal
    _shutdown_signal = signum
    _shutdown.set()


def install_signal_handlers():
    """Make `docker stop` work.

    /entrypoint.sh `exec`s gosu, so this process is PID 1 and receives SIGTERM directly.
    PID 1 gets no default signal dispositions from the kernel: without a handler the
    signal is dropped and the process is SIGKILLed after the grace period. ci/smoke.py
    check (k) fails the build if either half goes missing.

    SIGINT as well, so a foreground `docker run` and `make run` stop the same way.

    signal.signal() raises ValueError off the main thread; that only logs a warning and
    the servers start anyway. In the container run() is always on the main thread.
    """
    for signum in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(signum, request_shutdown)
        except (ValueError, OSError) as e:
            logger.warning(
                f"[Signals] No handler installed for {signal.Signals(signum).name}: {e}. "
                "This process will not shut itself down on that signal")


def _shutdown_reason():
    """What to name in the stop log line. Written once because run() leaves by two paths."""
    if _shutdown_signal is not None:
        return f"signal {signal.Signals(_shutdown_signal).name}"
    return "shutdown requested"


def run():
    # First, before anything that can block, so a stop during initial_domains() is recorded
    # rather than dropped by PID 1's empty signal dispositions.
    #
    # Under PEP 475 an interrupted syscall resumes after the handler, so a startup fetch out at a
    # black-holing PVE runs its full timeout. That must not hold the process: docker-compose.yml
    # raises the grace period, initial_domains() waits on the shutdown Event rather than on its
    # daemon fetch threads, and the `_shutdown.is_set()` check below returns before any bind.
    # ci/smoke.py check (k) does not cover this, since it stops a container long past startup.
    install_signal_handlers()

    # The client and the first fetch may come back empty when PVE is unreachable; the
    # servers start either way and the updater threads keep retrying. initial_domains()
    # publishes the zone itself under the shared lock and returns nothing to assign.
    initial_domains()

    # Leave before binding anything if the stop arrived during the fetch above; nothing is
    # open yet.
    if _shutdown.is_set():
        logger.log(logging.CRITICAL,
                   f"ProxDNS server stopped before startup ({_shutdown_reason()})")
        return

    def start_thread(target):
        while True:
            try:
                target()
            except Exception as e:
                logger.error(f"[Thread] Error in {target.__name__}: {e}")
                time.sleep(1)

    # One updater thread per host, so a host that stops answering delays none of the
    # others. start_thread() restarts a thread that raises.
    for host in _hosts:
        threading.Thread(target=lambda h=host: start_thread(_updater_for(h)), daemon=True).start()
    threading.Thread(target=lambda: start_thread(start_dns_server), daemon=True).start()
    threading.Thread(target=lambda: start_thread(start_http_server), daemon=True).start()

    logger.log(logging.CRITICAL, "ProxDNS server started")

    # Event.wait() returns True as soon as request_shutdown() sets the event and False on a
    # timeout, so the loop body is the periodic report and leaving the loop is the shutdown.
    while not _shutdown.wait(REPORT_INTERVAL):
        # One snapshot for the whole report: a host thread may rebind the list meanwhile.
        servers = state.servers_list
        if not servers:  # nothing yet; avoid max() on an empty list
            continue
        max_domain_length = max(len(server["domain"]) for server in servers)
        max_ipv4_length = max(len(server.get("ipv4", "")) for server in servers)
        max_ipv6_length = max(len(server.get("ipv6", "")) for server in servers)
        for server in servers:
            domain = server["domain"].ljust(max_domain_length)
            ipv4_address = server.get("ipv4", "--.--.--.--").ljust(max_ipv4_length)
            ipv6_address = server.get("ipv6", "--").ljust(max_ipv6_length)
            # Which host the name came from.
            source_host = server.get("host", "--")
            logger.debug(f"{domain}\t{ipv4_address}\t{ipv6_address}\t{source_host}")

    # CRITICAL like the startup line, so it survives any LOG_LEVEL: it shows the container
    # stopped because it was asked to.
    logger.log(logging.CRITICAL, f"ProxDNS server stopped ({_shutdown_reason()})")
