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

    The hosts are independent endpoints, so nothing here is shared between them —
    including `domains`, which is that host's last-known-good answer. Keeping the
    slices apart is what makes a failure isolated: a host that stops answering keeps
    the records it last published instead of taking them out of the merged zone, and
    a host that answers keeps refreshing regardless of what the others are doing.
    """

    def __init__(self, cfg):
        self.cfg = cfg
        self.client = None
        self.client_error_logged = False
        self.last_signature = None
        self.last_full_refresh = 0.0
        self.domains = []
        # Whether anything has ever filled `domains` for this host. Written only under
        # _publish_lock, and read only there: it is what lets a startup fetch that
        # answered AFTER the deadline publish its names without ever landing on top of
        # something this host's own updater published in the meantime. See the late
        # branch in initial_domains().
        self.has_published = False


# One entry per configured host, in PROXMOX_HOSTS order — which is also the order the
# merge breaks ties in, so the operator controls it by ordering the config.
_hosts = [HostState(cfg) for cfg in settings.proxmox_hosts]

# Held while a host swaps its own slice and the merged list is rebuilt from all of them.
# Several host threads publish concurrently, and each one reads every OTHER host's slice
# to do it.
_publish_lock = threading.Lock()

# Set by request_shutdown() when a stop signal arrives. The main loop WAITS on this instead of
# sleeping, which is the whole point: a bare time.sleep(30) would keep the process alive for up to
# another 30 s after `docker stop` had already taken the container out of service.
_shutdown = threading.Event()
# Which signal asked for the shutdown. Recorded here and logged AFTER the loop rather than from
# inside the handler: a signal handler runs between two bytecodes of whatever the main thread was
# doing, so the less it touches there, the fewer ways it has of re-entering something half-finished.
_shutdown_signal = None

# Seconds between the zone dumps the main loop logs.
REPORT_INTERVAL = 30

# How long run() waits for the startup fetch of ALL hosts before it binds the sockets
# without whatever has not answered yet. A CEILING on the wait, not a wait: the hosts
# are fetched concurrently, so a healthy start costs the slowest single host and not
# the sum, and the deadline only decides how long a host that is black-holing packets
# may hold the bind.
#
# Ten seconds, chosen against the two things on either side of it. Below: proxmoxer's
# default timeout is 5 s per request and the fetch is one node listing plus a
# guest-agent call per VM, so a host that is merely SLOW — a loaded PVE, a request that
# had to time out and be retried — still lands inside 10 s and keeps its names in the
# pre-fill. Above: `stop_grace_period` in docker-compose.yml is 45 s, sized for a stop
# that arrives while this fetch is out, so the fetch has to be a small fraction of it;
# 10 s leaves the shutdown the rest of that budget even in the worst case. And a host
# that misses the deadline loses only the pre-fill: its own updater thread starts
# `detect_interval` (2 s) later and publishes the moment it gets an answer.
INITIAL_FETCH_DEADLINE = 10
# How often the wait above re-checks whether the fetches are done. It is also the
# granularity at which a shutdown arriving mid-fetch is noticed, which is why it is
# small: the wait is on the shutdown Event itself, so a stop returns from it at once,
# and this value only bounds how long a COMPLETED fetch waits before being harvested.
INITIAL_FETCH_POLL = 0.1


def ensure_client(host):
    """Return one host's Proxmox client, building it on the first attempt that succeeds.

    WITH API TOKEN AUTH THE CONSTRUCTOR IS NO LONGER A NETWORK CALL, and that is a
    correction to what this docstring used to claim. proxmoxer's token auth only
    stores the user, token name and token value and assembles a `PVEAPIToken=...`
    header per request; it is the PASSWORD path that posts to /access/ticket from
    inside the constructor. So what is guarded here is configuration failure and
    whatever a future auth mode brings, not a dead PVE — an unreachable host now
    surfaces one layer later, on the first real request.

    The surrounding invariant is UNCHANGED and still load-bearing: nothing on the
    way to the DNS and HTTP threads may depend on Proxmox succeeding. It has to
    be, because initial_domains() below still makes real network calls. This
    process answers DNS for the whole internal network, and a PVE that is down
    when the container starts must not kill it before the DNS and HTTP servers
    ever bind — docker restarts the container, so that is a crash loop rather
    than one dead container, and the outage becomes total instead of partial.

    The restart policy is `always` rather than `unless-stopped`, which is a
    behavioural choice and not a spelling. They differ in exactly one case: a
    container an operator stopped ON PURPOSE. `unless-stopped` remembers that
    stop across a restart of the docker daemon and leaves the container down;
    `always` does not, and brings it back by itself the moment the daemon comes
    back. For the authoritative server of the whole internal `.lc` zone that is
    the wanted behaviour — a rebooted host must resolve names again without
    anyone logging in to start it — and the price is accepted knowingly: a
    deliberate stop only holds until the docker daemon next restarts.

    Returning None instead lets the servers come up and answer from whatever the
    list currently holds (empty right after start), and this host's updater
    thread retries on its next tick.
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

    Independent PVE hosts very probably run overlapping RFC1918 ranges, so two
    guests with different names can legitimately carry the same address — and
    unlike a name collision this is not something the merge may resolve. Both
    entries are real, both A records are right, and picking a winner would be
    guessing at which of two live guests the operator meant.

    What it DOES break is the reverse direction. src/dns_server.py answers a PTR
    by scanning the zone for the address and returning the first entry that
    carries it, so one of the two names is unreachable in reverse and which one
    depends on the order the list happens to be in. That is a failure mode a
    single host could not produce, so it is reported rather than hidden: this
    warning is the only place it exists.

    On every rebuild, like the collision warning in merge_domains(), and for the
    same reason — the condition stands for as long as both guests do, and a line
    that scrolled past during the incident is no use to whoever looks later.
    """
    # The sentinels src/proxmox.py stores for a guest it could not read an address
    # from. Every stopped guest carries them, so counting them would report a
    # "conflict" on every host that has more than one VM switched off.
    for field, sentinel in (("ipv4", "0.0.0.0"), ("ipv6", "::")):
        by_address = {}
        for entry in merged:
            address = entry.get(field)
            if not address or address == sentinel:
                continue
            by_address.setdefault(address, []).append(entry)
        for address, entries in by_address.items():
            if len({entry.get("host") for entry in entries}) < 2:
                # One host reusing an address is not this function's business: it is
                # either a duplicate name on one host or that host's own mistake, and
                # in neither case did merging several hosts create it.
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

    `per_host_lists` arrives in PROXMOX_HOSTS order, and that order is the tie-break:
    among equally good candidates the earliest host keeps the name, so the answer is
    deterministic and the operator controls it by ordering the config.

    ENTRIES ARE GROUPED BY HOST FIRST, and that is what keeps this function about the
    thing it was written for. The domain is the VM name's first segment, so `web-01`
    and `web-02` ON ONE HOST both produce `web.lc` — a duplicate that predates
    multi-host support entirely and that both the DNS server and the status page have
    always coped with. A host that is the ONLY claimant of a name therefore passes ALL
    of its entries through untouched: dropping the second one would take its address
    out of the zone, and with it the PTR answer for that guest, which src/dns_server.py
    can only give for an address that is somewhere in the list.

    A collision BETWEEN hosts is the case the policy is about, and there each host is
    ranked by its BEST entry. Three ranks, best first: running with a real address;
    running but with only the sentinels (the guest is up, the agent is missing or not
    answering); anything else, i.e. stopped. A running VM with no readable address
    still beats a stopped one — it is the guest that is actually there to be reached,
    whether or not we can say where yet. The winning HOST then contributes all of its
    entries for that name, so one host's internal duplicates survive its win.

    WITHIN a name, the entries are emitted BEST FIRST — by the same rank. src/dns_server.py
    answers an A query with the FIRST entry whose domain matches, so the emission order IS
    the answer, and grouping by host settles only which host's entries are emitted, not
    which of them comes first. Without the sort, `web-01` stopped and `web-02` running on
    the winning host would answer `web.lc` with the 0.0.0.0 sentinel that the stopped guest
    carries, while a perfectly healthy VM sat second in the list. That is not new with
    several hosts — ONE host with those two guests has always answered that way — and the
    sort fixes both cases at once. sorted() is stable, so entries of equal rank keep the
    order their host reported them in, and every entry stays in the list: nothing is
    dropped, so the PTR scan and the status page are unaffected.

    A genuine cross-host collision is logged at WARNING, on every rebuild rather than
    once: two hosts serving the same name is a configuration mistake, one host's guest
    is unreachable by name for as long as it lasts, and a line that scrolled past
    during the incident is no use to whoever looks later. A duplicate within ONE host
    is DEBUG instead — it is not necessarily a mistake, nothing about it changed here,
    and one warning a minute forever is not information.
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
            # Best first: the DNS server answers with the first match, so a stopped guest
            # listed ahead of a running one would resolve the name to the 0.0.0.0
            # sentinel. See the docstring. This is the branch where ONE host claims the
            # name, i.e. the case that predates multi-host support entirely.
            merged.extend(sorted(entries, key=_rank))
            continue

        # Rank every host by its best entry, then let the best host bring all of its
        # own. min() over `<` on the way in: an equal-ranked later host does not
        # displace an earlier one, which is what makes PROXMOX_HOSTS order the
        # tie-break.
        winner_index = min(by_host, key=lambda index: min(_rank(e) for e in by_host[index]))
        for host_index, entries in by_host.items():
            if host_index == winner_index:
                continue
            logger.warning(
                f"[Proxmox] Domain collision on {domain}: {_describe_claim(entries)} loses to "
                f"{_describe_claim(by_host[winner_index])}")
        # Best first, exactly as above: winning the collision decides the HOST, and this
        # decides which of that host's entries the DNS server actually answers with.
        merged.extend(sorted(by_host[winner_index], key=_rank))

    _warn_about_addresses_two_hosts_share(merged)
    return merged


def _publish_locked(host, domains):
    """Swap one slice and rebuild the zone. THE CALLER MUST HOLD _publish_lock.

    REBINDS state.servers_list rather than clearing and extending it. src/state.py
    is read through attribute lookup precisely so a reassignment is observed, and the
    difference is not cosmetic: clear() + extend() leaves a window in which a DNS
    query sees an empty list and answers NXDOMAIN for a name that exists. With one
    slice per host refreshing on its own thread that window is entered N times as
    often, and an NXDOMAIN is cached by whoever asked.
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

    Per host rather than one loop over all of them, and the reason is timing, not
    tidiness: get_domains() makes a guest-agent call per VM at proxmoxer's 5 s
    default timeout, so one black-holing host in a shared loop would hold every
    other host's refresh for minutes. N is a handful of homelab hosts, so N threads
    cost nothing worth counting.
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

    A bare lambda would do the binding just as well but would report every host's
    crash as `Error in <lambda>`, and with N threads running the same code the name
    is the only thing saying WHICH host died.
    """
    def run_updater():
        update_dns_periodically(host)

    run_updater.__name__ = f"update_dns_periodically({host.cfg.host})"
    return run_updater


def _initial_fetch(host):
    """One host's startup fetch. Returns its slice, or None if it could not be read.

    Everything that can fail on the Proxmox side at startup is contained here,
    because this runs BEFORE the DNS and HTTP threads exist: an exception escaping
    it would stop the process from ever serving the zone.

    get_domains() already degrades an unreachable API to None, but only for the
    two exception types it knows about. proxmoxer's AuthenticationError derives
    from plain Exception — it is neither a requests RequestException nor a
    ResourceException — so it goes straight through that guard. Inside the
    updater thread start_thread() would catch it; here there is nothing above us
    yet, which is exactly why the net is cast wide.
    """
    proxmox = ensure_client(host)
    if proxmox is None:
        return None
    try:
        return get_domains(proxmox, host.cfg.host)
    except Exception as e:
        logger.error(
            f"[Proxmox] {host.cfg.host}: initial domain fetch failed, "
            f"starting without its names: {e}")
        return None


def initial_domains():
    """Best-effort first fill of the zone across ALL hosts, before the servers are running.

    THE FETCHES RUN CONCURRENTLY, one short-lived thread per host, and that is not
    an optimisation. This is the one path where the zone is not being served yet, so
    the wait here is downtime; walking the hosts in turn would add up their timeouts,
    and with two dead hosts of a handful of VMs each the `.lc` zone would be
    unresolvable for the SUM of them. Concurrent, the wait is one slow host's latency,
    and INITIAL_FETCH_DEADLINE caps even that.

    So a host failing costs that host's names and nothing else — including nothing of
    anybody else's TIME, which is the part a sequential loop could not promise. A host
    that misses the deadline holds nothing back: the servers bind without it, and its
    answer goes into the zone whenever it arrives — from its own fetch thread if that
    thread is still the only one with an answer for it, otherwise from its updater.

    The pre-fill itself is deliberate and must not be dropped in favour of letting the
    updater threads do the first fill. Without it the DNS server binds and answers
    NXDOMAIN for real names until the first poll lands — and update_dns_periodically()
    sleeps `detect_interval` BEFORE its first poll — while a negative answer is cached
    by whoever asked. Not-yet-bound is a better failure than authoritative-and-wrong.

    The wait ABANDONS itself when the shutdown flag is set. A SIGTERM arriving during
    startup must not spend the grace period on a startup that is about to be thrown
    away; see the comment above install_signal_handlers() in run().

    PUBLISHES what it collected and RETURNS NOTHING. The reason is the late path below:
    a fetch that answers just after the deadline publishes on its own thread, and an
    assignment made by the caller afterwards would put the pre-deadline merge back on
    top of it. With no return value there is nothing for a caller — or a test — to read
    INSTEAD of state.servers_list, so both look at the one list the DNS server reads.
    """
    # Results are collected in slots rather than written straight into host.domains, so
    # that whether a fetch is on time is decided in ONE place. `harvested` is that
    # place's flag: the harvest below takes _publish_lock, sets it FIRST and reads the
    # slots AFTERWARDS, both inside that one critical section — and a fetch finding it
    # set knows its slot will never be looked at again and publishes its own answer
    # instead. Both sides read and write it under the lock, so there is no window in
    # which an answer is neither harvested nor published.
    #
    # A slot starts as `pending`, which is NOT None: None is what a fetch that RAN AND
    # FAILED stores, and the two have to be told apart. Only `pending` means "this host
    # has not answered yet", and only such a host may be named in the deadline warning
    # below — a failed fetch has already logged its own reason and missed no deadline.
    pending = object()
    slots = [pending] * len(_hosts)
    done = [threading.Event() for _ in _hosts]
    harvested = False

    def fetch(index, host):
        try:
            domains = _initial_fetch(host)
            # A LATE ANSWER IS PUBLISHED RATHER THAN THROWN AWAY, but only while nothing
            # else has filled this host's slice. A host with forty guests can genuinely
            # miss a 10 s deadline, and discarding what it says at 10.5 s makes its names
            # wait for a whole second full walk — doubling time-to-zone for exactly the
            # slow hosts the pre-fill exists for. What must never happen is this answer,
            # built before the sockets were bound, landing on top of a fresher one from
            # the host's own updater; `has_published` under the lock is what rules that
            # out, and the updater always wins because it publishes through the same lock.
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
        # Waiting on the SHUTDOWN Event rather than sleeping, which is what makes a
        # stop arriving mid-fetch cheap: wait() returns True the instant the handler
        # sets it, so run() reaches its `_shutdown.is_set()` check and returns instead
        # of sitting out the rest of the deadline on a startup it is abandoning. The
        # fetch threads are daemons, so whatever they are still blocked on dies with
        # the interpreter and holds nothing up.
        if _shutdown.wait(min(INITIAL_FETCH_POLL, remaining)):
            break

    # Under the lock, and not only out of habit. What it buys is that CLOSING the harvest
    # and READING the slots are ONE step, and what makes that airtight is the SLOTS
    # THEMSELVES: a slot is only ever written under this lock and only while `harvested`
    # is still false, so every slot that is filled when this block runs is by construction
    # an on-time answer, and every fetch that has not filled one yet finds `harvested`
    # set. What that fetch does next depends on what it is holding: an ANSWER goes into
    # the zone from its own thread, through the late branch above, and a FAILURE — None —
    # is nothing to publish at all, so the host simply keeps the slice it already had.
    # Neither case needs this harvest, which is what makes skipping them safe. This is
    # also the last moment at which the slices belong to this function alone.
    #
    # `done[index]` DELIBERATELY DOES NOT APPEAR HERE, and requiring it was a bug: it is
    # set in the fetch's `finally`, AFTER the lock is released, so a fetch that had
    # written its slot but not yet reached that line was skipped by this loop while its
    # own `on_time` was True — leaving the host's answer published by neither side and its
    # names NXDOMAIN until its updater's first successful poll.
    #
    # A straggler is NOT otherwise isolated, and the earlier claim that it "writes only to
    # its own slot" was wrong: _initial_fetch() calls ensure_client(), which writes
    # host.client and host.client_error_logged. What does hold is what matters here — a
    # straggler never writes host.domains except through the lock, and its slot is never
    # read again. The window that remains is real and small: after the deadline a late
    # fetch thread runs alongside that host's own updater, both may build a client, and
    # both then use the same proxmoxer requests.Session, which is not documented as
    # thread-safe.
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
            # BOOKKEEPING, NOT A GUARD. The only reader of this flag for THIS host is its
            # own fetch thread, which has already computed `on_time = True` and never
            # looks at the flag again — so there is no interleaving this line protects
            # against and the next reader should not go hunting for one. It is here to
            # keep the invariant HostState declares true, which is what the late branch
            # relies on for every other host.
            host.has_published = True
        state.servers_list = merge_domains([h.domains for h in _hosts])

    # Built from the slots the harvest just read rather than from `done`, and for the same
    # reason `done` is absent above: it lags the slot write by the width of a lock release,
    # so a list built from it can name a host whose answer is already in the zone.
    if late and not _shutdown.is_set():
        logger.warning(
            f"[Proxmox] {', '.join(late)}: no answer within {INITIAL_FETCH_DEADLINE} s, starting "
            "without their names rather than holding the DNS server back; they publish as soon "
            "as they answer, either from the fetch itself or from their own updater thread")


def request_shutdown(signum, _frame):
    """Handler for SIGTERM and SIGINT: ask the main loop to return.

    Deliberately does nothing but record the signal and set the Event. Everything else — the log
    line, the return out of run() — happens back on the main loop, where it is ordinary code
    rather than something running in the gap between two bytecodes.

    There is nothing to flush before exiting, and that is a property of this service rather than
    an oversight: it is stateless, it opens no file, it writes nothing to /app/data, and its only
    shared object is an in-memory list (src/state.py). The log handler is a StreamHandler, which
    flushes on every record. So returning from run() IS the clean shutdown — the three daemon
    threads holding the UDP and TCP sockets go down with the interpreter.

    ONE CAVEAT, STATED RATHER THAN ENGINEERED AROUND. Event.set() is not async-signal-safe:
    threading.Event is built on a Condition(Lock()), that lock is not reentrant, and a signal
    arriving in the microscopic window where the main thread already holds it inside Event.wait()
    would deadlock this handler — after which the process would sit out the grace period and be
    SIGKILLed. The window is a few instructions wide, it is entered once per REPORT_INTERVAL, and
    setting an Event from a handler is the standard python idiom. DO NOT "fix" it with
    signal.set_wakeup_fd(), a self-pipe or anything else: the replacement is strictly more machinery
    guarding against something that has never been observed, and this docstring exists so the next
    reader does not have to rediscover the trade-off in order to leave it alone.
    """
    global _shutdown_signal
    _shutdown_signal = signum
    _shutdown.set()


def install_signal_handlers():
    """Make `docker stop` work. BOTH halves below are required; neither is enough on its own.

    /entrypoint.sh `exec`s gosu, so the python process itself is PID 1 and the SIGTERM `docker
    stop` sends to PID 1 is DELIVERED here rather than to a shell that would have to forward it.
    That is the first half, and it is the one that is easy to mistake for the whole thing.

    The second half is this function. PID 1 gets NO default signal dispositions from the kernel:
    a signal for which PID 1 has installed no handler is DROPPED, not applied. So a python process
    that is PID 1 and never calls signal.signal() does not die on `docker stop` at all — it sits
    out the entire grace period (10 s by default) and is then SIGKILLed, on every redeploy of the
    server the whole `.lc` zone resolves through. Installing a handler is what turns the delivered
    signal into an exit. ci/smoke.py check (k) fails the build if either half goes missing.

    SIGINT as well as SIGTERM, so a `docker run` in a foreground terminal and a local `make run`
    stop the same way the deployment does.

    signal.signal() raises ValueError off the main thread, which is not a reason to refuse to
    serve DNS: the warning says the process will not stop on its own, and the servers start
    anyway. In the container run() is always on the main thread and this never fires.
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
    # First, before anything that can block, so a stop arriving during initial_domains() is at least
    # RECORDED rather than dropped by PID 1's empty signal dispositions.
    #
    # RECORDED IS NOT ACTED ON, and the gap between the two is what the machinery below is for.
    # Under PEP 475 CPython resumes an interrupted syscall once the handler returns, so a request a
    # startup fetch has out at a black-holing PVE runs its full proxmoxer timeout whenever the
    # signal lands. What that must not do is hold the PROCESS: with a 5 s default timeout per
    # per-VM guest-agent call, a handful of VMs behind a dead PVE overruns docker's 10 s default
    # grace period on its own, and the container is SIGKILLed on exit 137 — which ci/smoke.py check
    # (k) cannot catch, because it stops a container that is long past startup. Three things close
    # that gap: docker-compose.yml raises the grace period; initial_domains() waits on THIS Event
    # rather than on its fetch threads, which are daemons and die with the interpreter still
    # blocked; and the `_shutdown.is_set()` check below returns before a socket is ever bound.
    install_signal_handlers()

    # Both the client and the first fetch are allowed to come back empty when PVE
    # is unreachable — see ensure_client() and initial_domains(). The servers
    # below start either way, so the zone is served (empty at first) while the
    # updater thread keeps retrying the connection.
    #
    # It PUBLISHES the zone itself, under the same lock every other writer uses, and
    # returns nothing for this line to assign — deliberately: a host that answers just
    # after the deadline publishes from its own fetch thread, and an assignment made
    # here afterwards would put the pre-deadline merge back on top of it.
    initial_domains()

    # Leave before binding anything if the stop arrived during the fetch above. Cheap, and it turns
    # the worst case from "bind three sockets, log a start, then immediately tear it all down" into
    # a return. There is nothing to undo at this point: no socket is open and no thread is running.
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
    # others — see update_dns_periodically(). Each goes through the same start_thread()
    # wrapper, so a thread that raises is restarted exactly as the single one was.
    for host in _hosts:
        threading.Thread(target=lambda h=host: start_thread(_updater_for(h)), daemon=True).start()
    threading.Thread(target=lambda: start_thread(start_dns_server), daemon=True).start()
    threading.Thread(target=lambda: start_thread(start_http_server), daemon=True).start()

    logger.log(logging.CRITICAL, "ProxDNS server started")

    # Event.wait() and not time.sleep(): wait() returns the moment request_shutdown() sets the
    # event, so a stop is answered at once instead of up to REPORT_INTERVAL seconds later. It
    # returns True when the event is set and False on a timeout, which makes the loop body the
    # periodic report and leaving the loop the shutdown. On the main thread the wait is also
    # interruptible by the signal itself, so the handler runs immediately rather than at the end
    # of the current interval.
    while not _shutdown.wait(REPORT_INTERVAL):
        # One snapshot for the whole report: a host thread may rebind the list between
        # any two lookups, and measuring the columns against one list while printing
        # another is how a report ends up misaligned for no reason anyone can find.
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
            # Which host the name came from: with several hosts merged into one zone,
            # a report that does not say is unreadable the moment two of them clash.
            source_host = server.get("host", "--")
            logger.debug(f"{domain}\t{ipv4_address}\t{ipv6_address}\t{source_host}")

    # CRITICAL like the startup line, and for the same reason: it has to survive any LOG_LEVEL.
    # This is the line that tells whoever reads the log afterwards that the container went down
    # because it was ASKED to, rather than because something killed it.
    logger.log(logging.CRITICAL, f"ProxDNS server stopped ({_shutdown_reason()})")
