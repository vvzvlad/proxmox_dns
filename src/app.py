import logging
import signal
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


def ensure_client():
    """Return the shared Proxmox client, building it on the first attempt that succeeds.

    ProxmoxAPI authenticates EAGERLY inside its constructor (proxmoxer posts to
    /access/ticket), so an unreachable or rejecting PVE raises right here rather
    than later, on first use. Serving the zone must not depend on that: this
    process answers DNS for the whole internal network, and a PVE that is down
    when the container starts would otherwise kill it before the DNS and HTTP
    servers ever bind — and docker restarts the container, so that is a crash
    loop rather than one dead container, and the outage becomes total instead of
    partial.

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
    # RECORDED, not acted on, and the difference is the whole reason for the check further down.
    # Under PEP 475 CPython restarts an interrupted syscall once the handler returns, so a SIGTERM
    # landing while initial_domains() waits on an unreachable PVE sets the Event and then goes back
    # to waiting: the shutdown is only noticed when that call comes back. With proxmoxer's 5 s
    # default timeout on each per-VM guest-agent call, a handful of VMs behind a black-holing PVE
    # overruns the 10 s stop_grace_period on its own — and the container is SIGKILLed on exit 137,
    # which ci/smoke.py check (k) cannot catch because it stops a container that already passed
    # every startup marker. Two things narrow that: docker-compose.yml raises the grace period, and
    # the `_shutdown.is_set()` check below stops the process spending what is left of it on a
    # startup it is about to abandon.
    install_signal_handlers()

    # Both the client and the first fetch are allowed to come back empty when PVE
    # is unreachable — see ensure_client() and initial_domains(). The servers
    # below start either way, so the zone is served (empty at first) while the
    # updater thread keeps retrying the connection.
    initial = initial_domains()
    if initial:
        state.servers_list.extend(initial)

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

    threading.Thread(target=lambda: start_thread(update_dns_periodically), daemon=True).start()
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

    # CRITICAL like the startup line, and for the same reason: it has to survive any LOG_LEVEL.
    # This is the line that tells whoever reads the log afterwards that the container went down
    # because it was ASKED to, rather than because something killed it.
    logger.log(logging.CRITICAL, f"ProxDNS server stopped ({_shutdown_reason()})")
