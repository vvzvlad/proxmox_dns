"""Startup, shutdown and multi-host merge invariants of src/app.py.

Startup: whatever the Proxmox side does while the process starts, the DNS and HTTP
servers still come up. The service is authoritative for the internal `.lc` zone, and a
startup that dies before those threads exist becomes a restart loop. With token auth the
first network call is initial_domains(), one per configured host, so that is where these
tests put a failing PVE.

Shutdown: `docker stop` stops the process. In the container python is PID 1, which has no
default signal dispositions, so the tests check that the handler is installed, a stop during
startup is acted on before anything binds, and the reporting loop returns as soon as the
handler fires.

Multi-host: _isolate_module_state() installs one host by default, so these tests configure
two and assert what only a run over both produces: an updater per host, a startup fetch that
survives the first host failing and runs hosts concurrently, `_hosts` built from every
PROXMOX_HOSTS entry, the harvest (zone published with no answers; an answer in its slot is
harvested before its fetch thread finishes; late hosts named in the warning, failed ones
not), and late answers published but never over the host's own updater. Pre-fill assertions
read state.servers_list, since initial_domains() returns nothing.

Merge: a name served by two hosts resolves to the running guest; a silent host keeps its own
records and nobody else's change; a name claimed twice on one host keeps both entries (PTR
needs the address); one address from two hosts is reported, not resolved; within a name the
best entry comes first, since src/dns_server.py answers with the first match.
"""

import signal
import threading
import time

import pytest

from src import app, state
from src.settings import ProxmoxHost, settings

# How long to wait for a server thread to report in. Generous: it only has to
# cover thread scheduling, and a failing run pays this once.
STARTUP_WAIT = 5.0
# The same, for run() coming back after the shutdown Event is set.
SHUTDOWN_WAIT = 5.0
# How long the startup fetches are given to meet at a rendezvous. Only a sequential fetch
# spends it; the test then fails on the missing names.
RENDEZVOUS_WAIT = 5.0
# What "the startup fetch gave up promptly" means; well under app.INITIAL_FETCH_DEADLINE
# so that running the deadline out does not satisfy it.
ABANDON_WAIT = 3.0
# Hard bound on every Event a fake PVE blocks on to stand in for a host that never answers.
# A fuse, not a budget: a correct run never reaches it, and it turns a regression into a
# failure instead of a suite that never finishes.
BLACK_HOLE_BOUND = 30.0
# How long a late startup fetch thread is given to publish on its own; slack for a thread
# hand-off.
LATE_PUBLISH_WAIT = 5.0


@pytest.fixture
def saved_signal_handlers():
    """Put SIGTERM's and SIGINT's dispositions back after a test has called run().

    run() installs its own, and monkeypatch knows nothing about them. Without
    this the handler would outlive the test that provoked it: pytest's own Ctrl-C
    would stop raising KeyboardInterrupt and start setting a shutdown Event that
    belongs to a test which finished long ago.
    """
    saved = [(signum, signal.getsignal(signum))
             for signum in (signal.SIGTERM, signal.SIGINT)]
    yield
    for signum, handler in saved:
        signal.signal(signum, handler)


class _StopLoop(BaseException):
    """Sentinel used to unwind the infinite loops in src/app.py.

    Derived from BaseException because start_thread() catches Exception and would
    restart the loop.
    """


class _FakeClock:
    """Stand-in for the `time` module inside src/app.py.

    Injected as `app.time`, so it replaces the module reference in this one
    module and nothing else in the process. It ends the loop it is driving after
    `ticks` sleeps, and advances a virtual clock by the slept amount so
    time.time() moves the way the updater expects without any real waiting.
    """

    def __init__(self, ticks):
        self._ticks_left = ticks
        self._now = 0.0

    def sleep(self, seconds):
        if self._ticks_left <= 0:
            raise _StopLoop
        self._ticks_left -= 1
        self._now += seconds

    def time(self):
        return self._now

    def monotonic(self):
        """The third function src/app.py asks the `time` module for. NOT faked.

        initial_domains() builds its deadline from it, and on a frozen clock the
        deadline never expires, so a fetch that stopped returning would hang the suite
        (there is no pytest-timeout). The fetches here answer in microseconds, so the
        real clock costs nothing and a regression fails at INITIAL_FETCH_DEADLINE.
        """
        return time.monotonic()


class _ClockThatExpiresOnceTheFetchIsParked:
    """`time.monotonic()` for initial_domains(), driven by an Event instead of by a clock.

    One test needs the startup wait to end at the instant a fetch thread is parked
    between writing its slot and setting its done Event; a real-clock deadline would be
    a flake either way it is tuned. monotonic() stands still until the fetch is parked,
    then advances by more than the deadline on every call, so the wait gives up on its
    next look whichever side of the deadline computation the parking landed on.

    Also bounded in real time: if the fetch never parks, after BLACK_HOLE_BOUND seconds
    the clock advances anyway, and the test fails in _join_the_startup_fetch_of()
    instead of hanging the suite (there is no pytest-timeout).
    """

    def __init__(self, parked):
        self._parked = parked
        self._now = 0.0
        # Read once, so every later call measures the fuse from the same instant.
        self._started = time.monotonic()

    def monotonic(self):
        fuse_blown = time.monotonic() - self._started >= BLACK_HOLE_BOUND
        if not (self._parked.is_set() or fuse_blown):
            return self._now
        self._now += app.INITIAL_FETCH_DEADLINE + 1
        return self._now


class _LockThatParksAFetchOnItsWayOut:
    """src/app.py's `_publish_lock`, plus the window one test below is about.

    A startup fetch writes its slot inside the lock and sets its done Event in a
    `finally` after releasing it. This holds the fetch thread in that gap: slot written,
    lock free for the harvest, `done` unset. Only fetch threads are held (recognised by
    the `initial-fetch(` thread name), so the harvest passes through.

    It parks on the first release after `answered` is set (the test's get_domains()
    sets it as it returns), which is the release that carries the slot write; parking
    on any release would break if fetch() took this lock more than once. The test uses
    one host, so the Event cannot describe another host's fetch.

    Wraps a real Lock, so mutual exclusion is preserved.
    """

    def __init__(self, parked, proceed, answered):
        self._lock = threading.Lock()
        self._parked = parked
        self._proceed = proceed
        self._answered = answered

    def __enter__(self):
        self._lock.acquire()
        return self

    def __exit__(self, *_exc):
        self._lock.release()
        if (self._answered.is_set() and not self._parked.is_set()
                and threading.current_thread().name.startswith("initial-fetch(")):
            self._parked.set()
            # Bounded like every other black hole in this file: a regression that stops
            # the test from releasing this thread has to fail the suite, not wedge it.
            self._proceed.wait(BLACK_HOLE_BOUND)
        return False


class _RecordingEvent(threading.Event):
    """A shutdown Event that says whether run()'s REPORTING LOOP ever waited on it.

    Two places wait on it: the reporting loop for REPORT_INTERVAL and initial_domains()
    for INITIAL_FETCH_POLL. Only the former sets `waited`, so the flag cannot pass on a
    run() that never reached the loop.

    Everything else behaves exactly as threading.Event does.
    """

    def __init__(self):
        super().__init__()
        self.waited = threading.Event()
        # Every timeout seen, for the failure message.
        self.timeouts = []

    def wait(self, timeout=None):
        self.timeouts.append(timeout)
        if timeout == app.REPORT_INTERVAL:
            self.waited.set()
        return super().wait(timeout)


def _host_state(name):
    """One HostState with a throwaway config. The token authenticates nothing anywhere."""
    return app.HostState(ProxmoxHost(
        host=name, user="dns@pve", token_name="dns", token_value="not-a-real-token"))


def _isolate_module_state(monkeypatch, host_names=("pve1.test",)):
    """Reset the per-host states, the zone and the shutdown flag src/app.py keeps at module level.

    monkeypatch restores them afterwards, so one test's client or shutdown Event
    cannot leak into the next. Replacing `_hosts` (built from PROXMOX_HOSTS at import)
    is also how a test chooses how many hosts it exercises. Returns the list in
    PROXMOX_HOSTS order, the merge tie-break order.
    """
    hosts = [_host_state(name) for name in host_names]
    monkeypatch.setattr(app, "_hosts", hosts)
    monkeypatch.setattr(app, "_shutdown", threading.Event())
    monkeypatch.setattr(app, "_shutdown_signal", None)
    # publish_domains() rebinds state.servers_list, so tests read it through the module.
    monkeypatch.setattr(state, "servers_list", [])
    return hosts


def _parked_target(reported=None, then_stop=False):
    """A stand-in for one of the three loops run() hands to a thread.

    Sets `reported` if given, then blocks forever like the real targets; returning
    would make start_thread() spin. The thread is a daemon parked on an Event.

    The run() tests park the updater too: with a _FakeClock installed, the real updater
    would raise _StopLoop on a second thread; without one, it would make real calls.

    `then_stop` sets the shutdown Event once this target is reached, which is how a
    test says "the stop arrived after startup". Setting it before run() would take
    run()'s early-return path instead. `app._shutdown` is looked up at call time
    because _isolate_module_state() replaced it.
    """
    parked = threading.Event()

    def target(*_args):
        # *_args: the updater target takes the host, the server targets nothing.
        if reported is not None:
            reported.set()
        if then_stop:
            app._shutdown.set()
        parked.wait()

    return target


def _run_on_a_worker_thread():
    """Start run() on a daemon thread and hand back the Event that says it returned.

    run() must not be called on the main thread while its reporting loop is reachable:
    only an Event set from one of run()'s threads ends it, and if that never happens a
    main-thread call hangs the suite (there is no pytest-timeout). On a daemon thread
    every claim is a bounded Event wait and the worker dies with the interpreter.

    Off the main thread signal.signal() raises ValueError (install_signal_handlers()
    catches it), so tests using this helper say nothing about handlers. The two tests
    that call run() directly set the shutdown Event before run() passes
    initial_domains(), so they leave by the early return.
    """
    returned = threading.Event()

    def call_run():
        app.run()
        returned.set()

    threading.Thread(target=call_run, daemon=True).start()
    return returned


def test_run_starts_dns_and_http_when_the_proxmox_client_cannot_be_built(monkeypatch):
    """The regression: a client that cannot be built at startup must still leave the zone served.

    ensure_client() must return None on a configuration fault and startup must carry
    on; otherwise run() dies before any thread exists and the container restart-loops.
    """
    dns_started = threading.Event()
    http_started = threading.Event()

    def client_that_cannot_be_built(_cfg):
        raise RuntimeError("No valid authentication credentials were supplied")

    _isolate_module_state(monkeypatch)
    monkeypatch.setattr(app, "build_client", client_that_cannot_be_built)
    monkeypatch.setattr(app, "start_dns_server", _parked_target(dns_started))
    # The stop is asked for from inside the last thread run() starts, so the reporting
    # loop returns at once. A stop pending before run() would take the early-return path
    # instead (see _parked_target()).
    monkeypatch.setattr(app, "start_http_server",
                        _parked_target(http_started, then_stop=True))
    monkeypatch.setattr(app, "update_dns_periodically", _parked_target())
    # A clock that refuses to sleep, as a watchdog: a reporting loop that slept instead
    # of waiting on the Event raises _StopLoop on the worker, and `returned` fails at
    # SHUTDOWN_WAIT.
    monkeypatch.setattr(app, "time", _FakeClock(ticks=0))

    returned = _run_on_a_worker_thread()

    assert dns_started.wait(STARTUP_WAIT), (
        "run() never reached start_dns_server: an unreachable PVE at startup takes "
        "the whole .lc zone down with it")
    assert http_started.wait(STARTUP_WAIT), (
        "run() never reached start_http_server: the status page and the compose "
        "healthcheck it answers are both gone")
    assert returned.wait(SHUTDOWN_WAIT), (
        f"both servers came up, but run() was still going {SHUTDOWN_WAIT} s after "
        "the last of them asked for the stop, so the reporting loop is not "
        "answering the shutdown Event")


def test_run_starts_dns_and_http_when_the_first_domain_fetch_raises(monkeypatch):
    """The same invariant one step later: a client that builds, then a fetch that throws.

    get_domains() degrades only the two exception types it catches to None;
    proxmoxer's AuthenticationError derives from plain Exception, so
    initial_domains() must guard the call.
    """
    dns_started = threading.Event()
    http_started = threading.Event()

    def rejected_credentials(_proxmox, _host):
        raise RuntimeError("Couldn't authenticate user: dns@pve")

    _isolate_module_state(monkeypatch)
    monkeypatch.setattr(app, "build_client", lambda _cfg: object())
    monkeypatch.setattr(app, "get_domains", rejected_credentials)
    monkeypatch.setattr(app, "start_dns_server", _parked_target(dns_started))
    monkeypatch.setattr(app, "start_http_server",
                        _parked_target(http_started, then_stop=True))
    monkeypatch.setattr(app, "update_dns_periodically", _parked_target())
    monkeypatch.setattr(app, "time", _FakeClock(ticks=0))  # watchdog, see the test above

    returned = _run_on_a_worker_thread()

    assert dns_started.wait(STARTUP_WAIT), (
        "run() died on the initial domain fetch and never started the DNS server")
    assert http_started.wait(STARTUP_WAIT), (
        "run() died on the initial domain fetch and never started the HTTP server")
    assert returned.wait(SHUTDOWN_WAIT), (
        f"both servers came up, but run() was still going {SHUTDOWN_WAIT} s after "
        "the last of them asked for the stop")


def test_run_installs_a_handler_for_the_signals_a_container_is_stopped_with(
        monkeypatch, saved_signal_handlers):
    """Without this, `docker stop` does nothing at all until the kernel kills it.

    PID 1 has no default signal dispositions, so an unhandled SIGTERM is dropped and
    the process is SIGKILLed after the grace period. /entrypoint.sh `exec`s gosu, so
    python is PID 1. SIGTERM is what `docker stop` sends; SIGINT a foreground run.
    """
    _isolate_module_state(monkeypatch)
    monkeypatch.setattr(app, "build_client", lambda _cfg: object())
    monkeypatch.setattr(app, "get_domains", lambda _proxmox, _host: [])
    monkeypatch.setattr(app, "start_dns_server", _parked_target())
    monkeypatch.setattr(app, "start_http_server", _parked_target())
    monkeypatch.setattr(app, "update_dns_periodically", _parked_target())
    # Pre-set so run() takes the early-return path; handlers are installed before
    # anything that can block, so they are installed on that path too.
    app._shutdown.set()
    monkeypatch.setattr(app, "time", _FakeClock(ticks=0))  # watchdog, as above

    app.run()

    for signum in (signal.SIGTERM, signal.SIGINT):
        assert signal.getsignal(signum) is app.request_shutdown, (
            f"run() left {signal.Signals(signum).name} on "
            f"{signal.getsignal(signum)!r}. At PID 1 that means the signal is "
            "dropped by the kernel, so `docker stop` waits out its whole grace "
            "period and SIGKILLs a DNS server that never noticed it was asked "
            "to stop")


def test_run_leaves_without_binding_anything_when_the_stop_arrived_during_startup(
        monkeypatch, saved_signal_handlers):
    """A stop recorded during the initial fetch is acted on the moment that fetch returns.

    Under PEP 475 a SIGTERM during an initial fetch is not acted on until the call
    returns. run() must then return before binding :53 and :80, since every further
    step spends the grace period. None of the three stand-in targets may be reached.
    """
    dns_started = threading.Event()
    http_started = threading.Event()
    updater_started = threading.Event()

    def slow_pve_that_is_stopped_mid_fetch(_proxmox, _host):
        # Stands in for the blocking call: the signal arrives while it is out.
        app._shutdown.set()
        return []

    _isolate_module_state(monkeypatch)
    monkeypatch.setattr(app, "build_client", lambda _cfg: object())
    monkeypatch.setattr(app, "get_domains", slow_pve_that_is_stopped_mid_fetch)
    monkeypatch.setattr(app, "start_dns_server", _parked_target(dns_started))
    monkeypatch.setattr(app, "start_http_server", _parked_target(http_started))
    monkeypatch.setattr(app, "update_dns_periodically", _parked_target(updater_started))
    monkeypatch.setattr(app, "time", _FakeClock(ticks=0))  # watchdog, as above

    app.run()

    # A short wait rather than a bare is_set(): a thread that HAD been started
    # would need a moment to report, and this test must fail on that rather than
    # win the race against it.
    assert not dns_started.wait(0.5), (
        "run() bound :53 after the stop had already been recorded. The container "
        "is on its way down; every socket opened here is time spent against the "
        "grace period, at the end of which docker sends SIGKILL")
    assert not http_started.wait(0.5), (
        "run() started the HTTP server after the stop had already been recorded")
    assert not updater_started.wait(0.5), (
        "run() started the updater thread after the stop had already been recorded")


def test_the_main_loop_returns_as_soon_as_the_handler_fires(monkeypatch):
    """The wait must be interruptible, not a 30 s nap the shutdown has to sit out.

    run() goes on a worker thread (see _run_on_a_worker_thread()), so a regression to a
    bare `time.sleep(30)` fails at SHUTDOWN_WAIT instead of hanging.

    The stop must arrive after startup: run() returns early when the Event is already
    set, which would skip the loop. So the last thread run() starts reports in first.

    request_shutdown() is called directly rather than raising a real signal, which
    would kill pytest if the handler were missing.
    """
    _isolate_module_state(monkeypatch)
    # Records the loop waiting on it, so leaving via the early return cannot satisfy
    # the assertions below.
    shutdown = _RecordingEvent()
    monkeypatch.setattr(app, "_shutdown", shutdown)
    monkeypatch.setattr(app, "build_client", lambda _cfg: object())
    monkeypatch.setattr(app, "get_domains", lambda _proxmox, _host: [])
    monkeypatch.setattr(app, "start_dns_server", _parked_target())
    # The last of the three threads run() starts. No `then_stop`: the stop comes from
    # outside, after startup.
    http_started = threading.Event()
    monkeypatch.setattr(app, "start_http_server", _parked_target(http_started))
    monkeypatch.setattr(app, "update_dns_periodically", _parked_target())

    returned = _run_on_a_worker_thread()
    assert http_started.wait(STARTUP_WAIT), (
        f"run() had not started the HTTP thread {STARTUP_WAIT} s in, so this test "
        "cannot say the shutdown below arrives after startup — which is the only "
        "arrangement under which it exercises the loop at all")
    app.request_shutdown(signal.SIGTERM, None)

    assert returned.wait(SHUTDOWN_WAIT), (
        f"run() was still going {SHUTDOWN_WAIT} s after the shutdown was "
        "requested. Its loop is sleeping rather than waiting on the Event, so a "
        "`docker stop` is answered up to a full interval late — and the internal "
        "zone is unresolvable for every second of it")
    assert shutdown.waited.is_set(), (
        "run() returned without ever waiting on the shutdown Event for "
        f"REPORT_INTERVAL ({app.REPORT_INTERVAL} s); the waits it did make were "
        f"{shutdown.timeouts}, which are the startup fetch's. So it left by some path "
        "other than the reporting loop and this test proved nothing about that loop. "
        "A loop that sleeps instead of waiting looks exactly like this")
    assert app._shutdown_signal == signal.SIGTERM, (
        "the handler did not record which signal stopped the process, so the "
        "final log line cannot say whether it was asked to stop or was killed")


def test_updater_retries_a_failed_client_and_fills_the_zone_once_pve_answers(monkeypatch):
    """The other half of the fix: the updater keeps trying, and the zone fills up.

    Starting without a client is only survivable if something later builds one.
    This drives the updater through two failed attempts and a successful third,
    and then one more tick to show the built client is reused rather than
    rebuilt on every pass.
    """
    attempts = []
    client = object()
    domains = [{"domain": "foo.lc", "ipv4": "10.0.0.5", "ipv6": "fe80::1",
                "host": "pve1.test", "vmid": 100, "status": "running"}]

    def pve_up_on_the_third_try(cfg):
        assert cfg.host == "pve1.test", "the updater built a client for some other host's config"
        attempts.append(None)
        if len(attempts) < 3:
            raise ConnectionError("connection refused")
        return client

    def inventory(proxmox, _host):
        assert proxmox is client, "the updater polled with something other than the built client"
        return frozenset({(100, "foo-bar", "node1", "running")})

    def all_domains(proxmox, _host):
        assert proxmox is client, "the updater fetched with something other than the built client"
        return list(domains)

    hosts = _isolate_module_state(monkeypatch)
    monkeypatch.setattr(app, "build_client", pve_up_on_the_third_try)
    monkeypatch.setattr(app, "get_vm_inventory", inventory)
    monkeypatch.setattr(app, "get_domains", all_domains)
    # Four ticks: two that find PVE down, one that connects and refreshes, and a
    # fourth that must reuse the client. The fifth sleep ends the loop.
    monkeypatch.setattr(app, "time", _FakeClock(ticks=4))

    with pytest.raises(_StopLoop):
        app.update_dns_periodically(hosts[0])

    assert len(attempts) == 3, (
        f"expected two failed builds and one that took, got {len(attempts)} attempts: "
        "either the updater gave up after the first failure, or it rebuilds the client "
        "on every tick instead of caching it")
    # publish_domains() rebinds state.servers_list, so read it through the module.
    assert state.servers_list == domains, (
        f"the zone was not refreshed once PVE answered: {state.servers_list!r}")


def test_the_startup_fetch_names_a_host_that_shows_no_guests(monkeypatch, caplog):
    """An empty startup slice draws one ERROR naming the host; a slice with guests draws none."""
    hosts = _isolate_module_state(monkeypatch)
    monkeypatch.setattr(app, "build_client", lambda _cfg: object())
    monkeypatch.setattr(app, "get_domains", lambda _proxmox, _host: [])

    with caplog.at_level("ERROR"):
        assert app._initial_fetch(hosts[0]) == []
    errors = [r.getMessage() for r in caplog.records if r.levelname == "ERROR"]
    assert len(errors) == 1 and "pve1.test" in errors[0], (
        f"a host that showed no guests at startup was not named in exactly one ERROR: {errors}")

    caplog.clear()
    entries = [_entry("foo.lc", "pve1.test")]
    monkeypatch.setattr(app, "get_domains", lambda _proxmox, _host: list(entries))

    with caplog.at_level("ERROR"):
        assert app._initial_fetch(hosts[0]) == entries
    errors = [r.getMessage() for r in caplog.records if r.levelname == "ERROR"]
    assert errors == [], f"a host with guests drew an ERROR at startup: {errors}"


# --- Every configured host, not just the first one ------------------------------------
# _isolate_module_state() installs one host by default, so these tests configure two and
# assert what only a run over both produces; each walk of `_hosts` could otherwise be cut to
# `_hosts[:1]` unnoticed.


def test_run_starts_an_updater_for_every_configured_host(monkeypatch):
    """One thread per host is the entire point of the per-host design.

    A shared loop would stall every host behind one that black-holes packets. A run()
    that started only the first host's updater looks healthy while every other host's
    refresh is gone.
    """
    hosts = _isolate_module_state(monkeypatch, ["pve1.test", "pve2.test"])
    polled = set()
    all_polled = threading.Event()
    # Never released, like _parked_target(): a returning target would spin start_thread().
    parked = threading.Event()

    def updater(host):
        polled.add(host.cfg.host)
        if len(polled) == len(hosts):
            all_polled.set()
        parked.wait()

    monkeypatch.setattr(app, "build_client", lambda _cfg: object())
    monkeypatch.setattr(app, "get_domains", lambda _proxmox, _host: [])
    monkeypatch.setattr(app, "update_dns_periodically", updater)
    monkeypatch.setattr(app, "start_dns_server", _parked_target())
    http_started = threading.Event()
    monkeypatch.setattr(app, "start_http_server", _parked_target(http_started, then_stop=True))
    monkeypatch.setattr(app, "time", _FakeClock(ticks=0))  # watchdog, as above

    returned = _run_on_a_worker_thread()

    assert all_polled.wait(STARTUP_WAIT), (
        f"run() polled {sorted(polled)} and no more: a configured host has no updater "
        "thread, so its names are fetched once at startup and never refreshed again")
    assert polled == {"pve1.test", "pve2.test"}
    assert returned.wait(SHUTDOWN_WAIT), (
        "every updater started, but run() did not come back after the stop")


def test_initial_domains_fetches_every_host_even_when_the_first_one_fails(monkeypatch):
    """The startup fetch is N fetches, and the first one failing ends none of the others.

    The failure is on the first host, so giving up on the whole zone or only looking at
    `_hosts[0]` both produce an empty zone. Read through state.servers_list, since
    initial_domains() returns nothing.
    """
    _isolate_module_state(monkeypatch, ["pve1.test", "pve2.test"])
    monkeypatch.setattr(app, "build_client", lambda _cfg: object())

    def pve1_rejects_the_token(_proxmox, host):
        if host == "pve1.test":
            raise RuntimeError("Couldn't authenticate user: dns@pve")
        return [_entry("two.lc", "pve2.test", vmid=202, ipv4="10.0.0.6")]

    monkeypatch.setattr(app, "get_domains", pve1_rejects_the_token)

    app.initial_domains()

    assert _domains_by_host(state.servers_list) == {"two.lc": "pve2.test"}, (
        f"the startup fetch published {state.servers_list!r}. A host that failed took "
        "another host's names down with it, so the zone starts emptier than it needs to "
        "be and every one of those names is an NXDOMAIN somebody caches")


def test_the_initial_fetches_of_all_hosts_overlap_in_time(monkeypatch):
    """Concurrently, not one after another — on the one path where waiting is downtime.

    initial_domains() runs before the DNS socket is bound, so its duration is an outage.
    Each fetch returns only once every host is inside the fetch at the same moment; a
    sequential loop cannot assemble the barrier, so the hosts lose their names and the
    test fails on missing names rather than on timing.
    """
    hosts = _isolate_module_state(monkeypatch, ["pve1.test", "pve2.test"])
    monkeypatch.setattr(app, "build_client", lambda _cfg: object())
    rendezvous = threading.Barrier(len(hosts), timeout=RENDEZVOUS_WAIT)
    addresses = {"pve1.test": "10.0.0.5", "pve2.test": "10.0.0.6"}

    def fetch_that_waits_for_the_other_host(_proxmox, host):
        rendezvous.wait()
        return [_entry(host.split(".")[0] + ".lc", host, ipv4=addresses[host])]

    monkeypatch.setattr(app, "get_domains", fetch_that_waits_for_the_other_host)

    app.initial_domains()

    assert _domains_by_host(state.servers_list) == {
        "pve1.lc": "pve1.test", "pve2.lc": "pve2.test"}, (
        f"the startup fetch published {state.servers_list!r}. The hosts never met inside "
        "it, so they are being fetched one after another and the wait before the DNS "
        "server binds is the SUM of every host's latency")


def test_the_initial_fetch_gives_up_its_wait_when_a_stop_arrives(monkeypatch):
    """A SIGTERM during startup must not be paid for at the startup's own pace.

    Waiting out INITIAL_FETCH_DEADLINE for a host that never answers spends the grace
    period on a startup about to be discarded. pve2 never answers, so only the wait
    noticing the flag ends the call early; measured in real time on purpose.

    initial_domains() runs on a daemon thread, so a sequential-fetch regression fails at
    ABANDON_WAIT instead of hanging the suite. The black hole is bounded as well.
    """
    _isolate_module_state(monkeypatch, ["pve1.test", "pve2.test"])
    monkeypatch.setattr(app, "build_client", lambda _cfg: object())
    # Never set; the bound keeps a stuck fetch thread from outliving the run.
    black_hole = threading.Event()

    def pve2_never_answers(_proxmox, host):
        if host == "pve2.test":
            black_hole.wait(BLACK_HOLE_BOUND)
        return [_entry("one.lc", "pve1.test", vmid=101)]

    monkeypatch.setattr(app, "get_domains", pve2_never_answers)
    # The stop is recorded before the fetch begins: the same state as a SIGTERM that
    # lands mid-fetch after its handler has returned.
    app._shutdown.set()
    zone_before_the_fetch = state.servers_list

    returned = threading.Event()

    def call_initial_domains():
        app.initial_domains()
        returned.set()

    threading.Thread(target=call_initial_domains, daemon=True).start()

    # The wait is the measurement: it returns when the fetch returns.
    assert returned.wait(ABANDON_WAIT), (
        f"the startup fetch was still going {ABANDON_WAIT} s after being started with "
        f"the shutdown flag already set. It is waiting out its own "
        f"{app.INITIAL_FETCH_DEADLINE} s deadline — or one host's answer — on a startup "
        "that is being abandoned, and every second of it comes out of the container's "
        "stop_grace_period")

    # Abandoning the wait is not abandoning the publish: whatever arrived is still
    # written to the zone. Which host's names got in races the shutdown, so only the
    # rebind is asserted.
    assert state.servers_list is not zone_before_the_fetch, (
        "the startup fetch gave up its wait and published nothing at all: "
        "state.servers_list still holds the object it held before the fetch ran. The "
        "write inside initial_domains() is the only path the pre-fill has into the zone")

    # Let the parked fetch finish inside this test (see _join_the_startup_fetch_of).
    black_hole.set()
    _join_the_startup_fetch_of("pve2.test")


def _join_the_startup_fetch_of(host_name):
    """Wait, BOUNDED, for one host's startup-fetch thread to finish.

    initial_domains() names those threads after their host. A thread that already
    finished is not enumerated, which is a pass.

    Every test that parks a fetch thread must release and join it here: on waking it
    takes the late-publish path, and after monkeypatch has restored the real `_hosts`
    and `state.servers_list` it would write into another test's state.
    """
    for thread in threading.enumerate():
        if thread.name == f"initial-fetch({host_name})":
            thread.join(LATE_PUBLISH_WAIT)
            assert not thread.is_alive(), (
                f"{host_name}'s startup fetch was still running {LATE_PUBLISH_WAIT} s "
                "after it was released")
            return


def test_a_host_that_answers_after_the_deadline_still_publishes_its_names(monkeypatch):
    """A late answer goes into the zone; it is not thrown away for being late.

    A host with many guests can miss the deadline; discarding its answer would make its
    names wait for a full updater walk. pve2 is held past a tiny deadline and released
    after initial_domains() returned, so the publish under test is the late path.
    """
    _isolate_module_state(monkeypatch, ["pve1.test", "pve2.test"])
    monkeypatch.setattr(app, "build_client", lambda _cfg: object())
    # Short so the test outlasts it quickly; the value itself is not under test.
    monkeypatch.setattr(app, "INITIAL_FETCH_DEADLINE", 0.2)
    answer = threading.Event()
    addresses = {"pve1.test": "10.0.0.5", "pve2.test": "10.0.0.6"}

    def pve2_answers_after_the_deadline(_proxmox, host):
        if host == "pve2.test":
            answer.wait(BLACK_HOLE_BOUND)
        return [_entry(host.split(".")[0] + ".lc", host, ipv4=addresses[host])]

    monkeypatch.setattr(app, "get_domains", pve2_answers_after_the_deadline)

    app.initial_domains()
    assert _domains_by_host(state.servers_list) == {"pve1.lc": "pve1.test"}, (
        f"the startup fetch published {state.servers_list!r}: pve2 was still blocked, so "
        "a deadline that had fired cannot be what produced this and the rest of the test "
        "would be proving something else")

    answer.set()
    _join_the_startup_fetch_of("pve2.test")

    assert _domains_by_host(state.servers_list) == {
        "pve1.lc": "pve1.test", "pve2.lc": "pve2.test"}, (
        f"the zone is {state.servers_list!r}. A host that answered just after the "
        "deadline had its answer discarded, so its names are NXDOMAIN until its own "
        "updater completes a full walk of its own")


def test_a_late_startup_fetch_never_lands_on_top_of_the_updaters_own_slice(monkeypatch):
    """The other half of it: late is allowed, stale is not.

    The late answer was built before the sockets were bound; if the host's updater has
    already published something newer, the late answer must not overwrite it.
    """
    hosts = _isolate_module_state(monkeypatch, ["pve1.test", "pve2.test"])
    monkeypatch.setattr(app, "build_client", lambda _cfg: object())
    monkeypatch.setattr(app, "INITIAL_FETCH_DEADLINE", 0.2)
    answer = threading.Event()

    def pve2_answers_after_the_deadline(_proxmox, host):
        if host == "pve2.test":
            answer.wait(BLACK_HOLE_BOUND)
            return [_entry("two.lc", "pve2.test", vmid=202, ipv4="10.0.0.6")]
        return [_entry("one.lc", "pve1.test", vmid=101, ipv4="10.0.0.5")]

    monkeypatch.setattr(app, "get_domains", pve2_answers_after_the_deadline)

    app.initial_domains()
    # pve2's own updater gets there first.
    app.publish_domains(hosts[1], [_entry("two.lc", "pve2.test", vmid=202, ipv4="10.0.0.99")])

    answer.set()
    _join_the_startup_fetch_of("pve2.test")

    served = {entry["domain"]: entry["ipv4"] for entry in state.servers_list}
    assert served == {"one.lc": "10.0.0.5", "two.lc": "10.0.0.99"}, (
        f"the zone is {state.servers_list!r}. The startup fetch published on top of what "
        "the host's own updater had already published, so the zone went backwards to an "
        "address read before the DNS server was even listening")


def test_the_startup_prefill_publishes_the_zone_even_when_no_host_answers(monkeypatch):
    """The pre-fill's own write, which nothing else in this file can see.

    initial_domains() returns nothing and run() assigns nothing, so the rebind inside it
    is the only path by which the pre-fill reaches the DNS server. Every host fails, so
    the published zone is empty; merge_domains() always builds a new list, so the rebind
    itself is what is asserted.
    """
    _isolate_module_state(monkeypatch, ["pve1.test", "pve2.test"])
    monkeypatch.setattr(app, "build_client", lambda _cfg: object())

    def every_host_rejects_the_token(_proxmox, _host):
        raise RuntimeError("Couldn't authenticate user: dns@pve")

    monkeypatch.setattr(app, "get_domains", every_host_rejects_the_token)
    zone_before_the_fetch = state.servers_list

    app.initial_domains()

    assert state.servers_list == [], (
        f"no host answered, yet the zone is {state.servers_list!r}")
    assert state.servers_list is not zone_before_the_fetch, (
        "the startup fetch left state.servers_list as it found it instead of publishing "
        "the zone it assembled. Nothing else assigns that name before the updater "
        "threads exist, so the pre-fill never reaches the DNS server at all")


def test_an_answer_already_in_its_slot_is_harvested_before_its_fetch_finishes(
        monkeypatch, caplog):
    """The harvest reads the SLOTS, and `done` is set later — from outside the lock.

    A fetch writes its slot inside _publish_lock and sets `done` in a `finally` after the
    lock is released. In between, the answer is on time (the fetch will not publish it
    itself) while `done` is unset; a harvest that also required `done` would skip it,
    and the host's names would be NXDOMAIN until its updater's first successful poll.

    The substituted lock holds the fetch thread in that window and the substituted clock
    expires the deadline at that moment, so the harvest always runs inside it. Neither
    changes what src/app.py does.
    """
    _isolate_module_state(monkeypatch, ["pve1.test"])
    parked = threading.Event()
    proceed = threading.Event()
    # Set as the answer comes back, so the lock double can tell the release that carries
    # the slot write (see _LockThatParksAFetchOnItsWayOut).
    answered = threading.Event()
    monkeypatch.setattr(app, "build_client", lambda _cfg: object())

    def one_host_that_says_when_its_answer_is_in_hand(_proxmox, host):
        entries = [_entry("one.lc", host, vmid=101, ipv4="10.0.0.5")]
        answered.set()
        return entries

    monkeypatch.setattr(app, "get_domains", one_host_that_says_when_its_answer_is_in_hand)
    monkeypatch.setattr(app, "_publish_lock",
                        _LockThatParksAFetchOnItsWayOut(parked, proceed, answered))
    monkeypatch.setattr(app, "time", _ClockThatExpiresOnceTheFetchIsParked(parked))

    with caplog.at_level("WARNING"):
        app.initial_domains()

    # Released and joined before asserting, so a failure does not leave a parked thread
    # (see _join_the_startup_fetch_of).
    proceed.set()
    _join_the_startup_fetch_of("pve1.test")

    assert parked.is_set(), (
        "the fetch thread never reached the window between its slot write and its done "
        "Event, so this test proved nothing about the harvest")
    assert _domains_by_host(state.servers_list) == {"one.lc": "pve1.test"}, (
        f"the zone is {state.servers_list!r}. The host's answer was in its slot, on time "
        "and under the lock, and the harvest walked past it because the fetch thread had "
        "not set its done Event yet — so nothing published it and the host lost its whole "
        "slice of the zone")
    assert "no answer within" not in caplog.text, (
        f"the startup fetch warned that a host had not answered:\n{caplog.text}\n"
        "pve1.test answered on time and its names are in the zone. The list in that "
        "warning is built from the fetch threads' done Events, which lag the slot write "
        "by the width of a lock release, so it names hosts that did answer")


def test_a_host_that_did_not_answer_by_the_deadline_is_named_in_the_warning(
        monkeypatch, caplog):
    """The positive half of that warning, without which the negative halves prove nothing.

    Two other tests assert a host is NOT named in this message; without this one,
    removing or rewording the warning would leave them green. pve2 is held past a tiny
    deadline while pve1 answers at once.
    """
    _isolate_module_state(monkeypatch, ["pve1.test", "pve2.test"])
    monkeypatch.setattr(app, "build_client", lambda _cfg: object())
    # Shrunk as in the late-publish test; the value is not under test.
    monkeypatch.setattr(app, "INITIAL_FETCH_DEADLINE", 0.2)
    answer = threading.Event()
    addresses = {"pve1.test": "10.0.0.5", "pve2.test": "10.0.0.6"}

    def pve2_is_still_working_when_the_deadline_fires(_proxmox, host):
        if host == "pve2.test":
            answer.wait(BLACK_HOLE_BOUND)
        return [_entry(host.split(".")[0] + ".lc", host, ipv4=addresses[host])]

    monkeypatch.setattr(app, "get_domains", pve2_is_still_working_when_the_deadline_fires)

    with caplog.at_level("WARNING"):
        app.initial_domains()
    # Read while pve2 is still blocked: the late publish after the release changes both.
    zone = _domains_by_host(state.servers_list)
    warning = caplog.text

    # Released and joined before asserting (see _join_the_startup_fetch_of).
    answer.set()
    _join_the_startup_fetch_of("pve2.test")

    assert zone == {"pve1.lc": "pve1.test"}, (
        f"the startup fetch published {zone!r}: pve2 was still blocked, so a "
        "deadline that had fired cannot be what produced this and the warning below would "
        "be about something else")
    assert f"pve2.test: no answer within {app.INITIAL_FETCH_DEADLINE} s" in warning, (
        f"pve2.test had not answered when the deadline fired, and the startup fetch "
        f"logged:\n{warning}\nThe servers are up and one host's names are missing from the "
        "zone they answer from; this warning is the only place that is stated at all")
    assert "pve1.test" not in warning, (
        f"pve1.test answered well inside the deadline and was named as late anyway:\n"
        f"{warning}\nThe list in that warning comes from the slots, so a host with an "
        "answer in its slot cannot be in it")


def test_a_host_whose_fetch_failed_in_time_is_not_named_in_the_deadline_warning(
        monkeypatch, caplog):
    """A FAILURE IS NOT A MISSED DEADLINE, and the slots are the only thing telling them apart.

    A slot starts as a `pending` sentinel rather than None, because None is what a fetch
    that ran and failed stores. Collapsing the two keeps the zone correct but reports a
    host that failed in 200 ms as silent for INITIAL_FETCH_DEADLINE, contradicting its
    own ERROR and pointing the reader at the network instead of the credential.

    pve1 fails at once; pve2 answers normally. Nothing is late, so no warning.
    """
    _isolate_module_state(monkeypatch, ["pve1.test", "pve2.test"])
    monkeypatch.setattr(app, "build_client", lambda _cfg: object())

    def pve1_says_at_once_that_its_token_is_no_good(_proxmox, host):
        if host == "pve1.test":
            raise RuntimeError("401 Unauthorized: invalid API token")
        return [_entry("two.lc", "pve2.test", vmid=202, ipv4="10.0.0.6")]

    monkeypatch.setattr(app, "get_domains", pve1_says_at_once_that_its_token_is_no_good)

    with caplog.at_level("WARNING"):
        app.initial_domains()

    assert _domains_by_host(state.servers_list) == {"two.lc": "pve2.test"}, (
        f"the startup fetch published {state.servers_list!r}, so the harvest whose warning "
        "this test is about did not run the way the test assumes")
    assert "no answer within" not in caplog.text, (
        f"pve1.test failed instantly and the startup fetch reported it as not having "
        f"answered within {app.INITIAL_FETCH_DEADLINE} s:\n{caplog.text}\nThose are two "
        "different states and only one of them is about time. A failed fetch has already "
        "logged its own reason; a deadline warning stacked on top of it contradicts that "
        "line and sends the next reader looking at the network instead of at the "
        "credential")
    assert "initial domain fetch failed" in caplog.text, (
        f"pve1.test's fetch failed without recording why:\n{caplog.text}\nThat ERROR is "
        "the line the operator is meant to act on, and the assertion above is only worth "
        "making while it exists")


def test_a_state_is_built_for_every_entry_of_proxmox_hosts():
    """`_hosts` is the list all three of the tests above walk. It is built once, at import.

    Every other test replaces `_hosts`, so a `_hosts` built from
    `settings.proxmox_hosts[:1]` would pass them all. tests/conftest.py configures two
    hosts so the comparison means something.
    """
    configured = [cfg.host for cfg in settings.proxmox_hosts]

    assert len(configured) > 1, (
        "tests/conftest.py is supposed to configure more than one host, precisely so "
        "this test can tell a list built from all of them from one built from the first")
    assert [host.cfg.host for host in app._hosts] == configured, (
        f"src/app.py holds states for {[h.cfg.host for h in app._hosts]} but "
        f"{configured} are configured. A host with no state is never polled, never "
        "publishes and contributes nothing to the zone")


# --- The merge across independent hosts ---------------------------------------------
# Everything below is about ONE zone assembled from N hosts that do not know about each
# other. Two guests on two hosts CAN end up claiming the same name — the domain is the
# VM name's first segment, and nothing coordinates naming between standalone hosts — so
# the merge has to pick one, pick the useful one, and say that it happened.


def _entry(domain, host, vmid=100, status="running", ipv4="10.0.0.5", ipv6="::"):
    """One entry in the shape src/proxmox.py hands back, sentinels included.

    The defaults describe the ordinary case — a running guest whose agent answered
    with an IPv4 — so a test names only the field it is actually about. `0.0.0.0` and
    `::` are not placeholders here: they are the sentinels src/proxmox.py stores when
    it could not read an address, and the merge ranks on exactly them.
    """
    return {"domain": domain, "ipv4": ipv4, "ipv6": ipv6,
            "host": host, "vmid": vmid, "status": status}


def _domains_by_host(merged):
    """{domain: host} — what the merge decided, without the fields nobody asserts on."""
    return {entry["domain"]: entry["host"] for entry in merged}


def _unreachable_get_domains(_proxmox, _host):
    """Fails the test rather than answering.

    With the cheap inventory poll already down, the expensive per-VM fetch must not be
    reached at all: it is one guest-agent call per VM at proxmoxer's 5 s timeout, and a
    host that is black-holing packets would spend the whole tick in it.
    """
    raise AssertionError(
        "the updater called get_domains for a host whose inventory poll had already "
        "failed, so a dead host costs a guest-agent call per VM on every tick")


def test_a_running_vm_wins_a_collision_against_a_stopped_one():
    """The collision policy, and the only one an operator was asked to remember.

    A stopped guest carries the `0.0.0.0` / `::` sentinels, so letting it win would
    resolve a name that IS reachable to an address that answers nothing. Asserted in
    both host orders, because a merge that simply kept the last entry it saw would
    pass one of them by accident.

    The second pair is where the RUN STATE is what decides, and it is the pair worth
    having: src/proxmox.py gives a stopped guest the sentinels, so against a running
    guest that HAS an address the address alone would settle it and a merge that never
    looked at `status` would still look correct. Against a running guest whose agent
    said nothing, nothing but `status` separates them.
    """
    running = [_entry("shared.lc", "pve1.test", vmid=101)]
    stopped = [_entry("shared.lc", "pve2.test", vmid=202, status="stopped",
                      ipv4="0.0.0.0", ipv6="::")]

    assert _domains_by_host(app.merge_domains([running, stopped])) == {"shared.lc": "pve1.test"}
    assert _domains_by_host(app.merge_domains([stopped, running])) == {"shared.lc": "pve1.test"}, (
        "the stopped guest won because it came first: the merge is keeping whatever it "
        "saw first rather than ranking the candidates")

    agentless = [_entry("shared.lc", "pve2.test", vmid=202, ipv4="0.0.0.0", ipv6="::")]
    stopped_elsewhere = [_entry("shared.lc", "pve3.test", vmid=303, status="stopped",
                                ipv4="0.0.0.0", ipv6="::")]
    assert _domains_by_host(app.merge_domains([stopped_elsewhere, agentless])) == {
        "shared.lc": "pve2.test"}, (
        "a stopped guest tied with a running one and won on host order, so the run "
        "state is not being ranked at all — both of them look equally address-less")
    assert _domains_by_host(app.merge_domains([agentless, stopped_elsewhere])) == {
        "shared.lc": "pve2.test"}


def test_a_running_vm_with_an_address_beats_a_running_one_without():
    """Second rank: up, but the guest agent is missing or not answering.

    Both candidates are running, so the run state cannot separate them. The one that
    can actually be resolved to an address is the one worth serving; the other would
    hand every client `0.0.0.0`.
    """
    with_address = [_entry("shared.lc", "pve1.test", vmid=101, ipv4="10.0.0.5")]
    no_address = [_entry("shared.lc", "pve2.test", vmid=202, ipv4="0.0.0.0", ipv6="::")]

    assert _domains_by_host(app.merge_domains([with_address, no_address])) == {
        "shared.lc": "pve1.test"}
    assert _domains_by_host(app.merge_domains([no_address, with_address])) == {
        "shared.lc": "pve1.test"}, (
        "a running guest with no readable address won over one with an address, so the "
        "name resolves to the 0.0.0.0 sentinel")


def test_an_ipv6_only_guest_counts_as_having_an_address():
    """The rank asks for AN address, not specifically an IPv4 one.

    A guest that answered with IPv6 only still keeps the `0.0.0.0` sentinel in its v4
    field, so a rank that looked at ipv4 alone would file it with the guests nothing
    could be read from at all.
    """
    ipv6_only = [_entry("shared.lc", "pve1.test", ipv4="0.0.0.0", ipv6="fe80::1")]
    nothing = [_entry("shared.lc", "pve2.test", ipv4="0.0.0.0", ipv6="::")]

    assert _domains_by_host(app.merge_domains([nothing, ipv6_only])) == {"shared.lc": "pve1.test"}


def test_equal_candidates_break_the_tie_by_the_order_of_proxmox_hosts():
    """Two identical claims have to resolve the SAME WAY on every refresh.

    Nothing distinguishes these two guests, so the merge cannot prefer either on its
    merits — and picking by dict iteration or by whichever thread published last would
    make the name flip between two addresses at random. The order of PROXMOX_HOSTS is
    the tie-break, which also means the operator can decide it.
    """
    first = [_entry("shared.lc", "pve1.test", vmid=101, ipv4="10.0.0.5")]
    second = [_entry("shared.lc", "pve2.test", vmid=202, ipv4="10.0.0.6")]

    assert _domains_by_host(app.merge_domains([first, second])) == {"shared.lc": "pve1.test"}
    assert _domains_by_host(app.merge_domains([second, first])) == {"shared.lc": "pve2.test"}, (
        "the tie did not follow the order of the lists, so it follows something the "
        "operator cannot see or control")


def test_names_that_do_not_collide_all_survive_the_merge():
    """The ordinary case: N hosts, one zone, nothing lost on the way in.

    An address each, so nothing here also trips the warning about one address arriving
    from two hosts — that is a different test's business.
    """
    merged = app.merge_domains([
        [_entry("a.lc", "pve1.test", ipv4="10.0.0.5"),
         _entry("b.lc", "pve1.test", ipv4="10.0.0.6")],
        [_entry("c.lc", "pve2.test", ipv4="10.0.0.7")],
    ])
    assert _domains_by_host(merged) == {
        "a.lc": "pve1.test", "b.lc": "pve1.test", "c.lc": "pve2.test"}


def test_a_collision_is_logged_with_both_hosts_and_both_vmids(caplog):
    """Two hosts serving one name is a configuration mistake nobody else will report.

    The loser's guest is unreachable by name for as long as it lasts, and the only
    place that fact exists is this log line — so it has to carry enough to act on:
    the name, both hosts, both vmids, and which of them won.
    """
    with caplog.at_level("WARNING"):
        app.merge_domains([
            [_entry("shared.lc", "pve1.test", vmid=101, status="stopped",
                    ipv4="0.0.0.0", ipv6="::")],
            [_entry("shared.lc", "pve2.test", vmid=202)],
        ])

    assert len(caplog.records) == 1, (
        f"expected exactly one collision warning, got {[r.getMessage() for r in caplog.records]}")
    message = caplog.text
    for fragment in ("shared.lc", "pve1.test", "pve2.test", "101", "202"):
        assert fragment in message, (
            f"the collision warning does not mention {fragment!r}, so it does not say "
            f"enough to act on:\n{message}")


def test_two_guests_with_one_name_on_ONE_host_both_stay_in_the_zone():
    """A duplicate within one host is not a cross-host collision.

    The domain is the VM name's first segment, so `web-01` and `web-02` on the same host
    both produce `web.lc`. Deduping by domain alone would drop an entry and its address:
    src/dns_server.py answers a PTR by scanning the list for the address, so that guest's
    reverse lookup would answer NXDOMAIN, and the status page would lose its row.
    """
    merged = app.merge_domains([[
        _entry("web.lc", "pve1.test", vmid=101, ipv4="10.0.0.5"),
        _entry("web.lc", "pve1.test", vmid=102, ipv4="10.0.0.6"),
    ]])

    assert [entry["ipv4"] for entry in merged] == ["10.0.0.5", "10.0.0.6"], (
        f"the merge kept {merged!r}. Two guests on one host that share a name are not a "
        "collision between hosts, and the dropped one's address is no longer anywhere in "
        "the zone — so a PTR query for it now answers NXDOMAIN")


def test_a_duplicate_within_one_host_is_logged_at_debug_rather_than_warning(caplog):
    """A within-host duplicate is DEBUG, not WARNING.

    The merge runs on every rebuild, so a WARNING would be a line per host per refresh
    for as long as both guests exist.
    """
    entries = [
        _entry("web.lc", "pve1.test", vmid=101, ipv4="10.0.0.5"),
        _entry("web.lc", "pve1.test", vmid=102, ipv4="10.0.0.6"),
    ]

    with caplog.at_level("WARNING"):
        app.merge_domains([entries])
    assert caplog.records == [], (
        "two guests on ONE host were reported as a collision: "
        f"{[r.getMessage() for r in caplog.records]}")

    caplog.clear()
    # The application logger, by name: at_level() on the root logger alone would not
    # help, because the record is filtered at src/logging_setup.py's own logger — whose
    # level is LOG_LEVEL, i.e. INFO — before it ever propagates.
    with caplog.at_level("DEBUG", logger=app.logger.name):
        app.merge_domains([entries])
    assert any("web.lc" in record.getMessage() for record in caplog.records), (
        "the duplicate is not recorded at all, so nothing says why one name has two "
        f"addresses in the zone: {[r.getMessage() for r in caplog.records]}")


def test_the_host_that_wins_a_collision_brings_all_of_its_own_entries():
    """The winner of a collision is a HOST, not an entry.

    pve2 has two guests claiming the name and pve1 has one that is stopped. Ranking
    entries individually would emit pve2's best one and drop its second — the same lost
    PTR as the single-host case above, only harder to see because a real collision is
    being resolved at the same time.
    """
    stopped = [_entry("web.lc", "pve1.test", vmid=101, status="stopped",
                      ipv4="0.0.0.0", ipv6="::")]
    two_running = [_entry("web.lc", "pve2.test", vmid=201, ipv4="10.0.0.5"),
                   _entry("web.lc", "pve2.test", vmid=202, ipv4="10.0.0.6")]

    merged = app.merge_domains([stopped, two_running])

    assert [(entry["host"], entry["vmid"]) for entry in merged] == [
        ("pve2.test", 201), ("pve2.test", 202)], (
        f"the merge kept {merged!r}: the winning host did not bring all of its entries")


def test_a_host_is_ranked_by_its_BEST_entry_rather_than_by_its_first():
    """With several entries per host, "which host wins" needs a rule of its own.

    pve1 reports a stopped guest first and a running, addressable one second. Ranking a
    host by whatever it happened to list first would hand the name to pve2's
    address-less guest and resolve it to the 0.0.0.0 sentinel.
    """
    mixed = [_entry("web.lc", "pve1.test", vmid=101, status="stopped",
                    ipv4="0.0.0.0", ipv6="::"),
             _entry("web.lc", "pve1.test", vmid=102, ipv4="10.0.0.5")]
    agentless = [_entry("web.lc", "pve2.test", vmid=201, ipv4="0.0.0.0", ipv6="::")]

    merged = app.merge_domains([agentless, mixed])

    assert {entry["host"] for entry in merged} == {"pve1.test"}, (
        f"the merge kept {merged!r}, so the host with a reachable guest lost the name")


def _first_answer_for(merged, domain):
    """The entry src/dns_server.py would answer an A query with.

    It scans state.servers_list and returns on the FIRST entry whose domain matches, so
    the merge's emission order is the answer. Written out here rather than asserted as
    `merged[0]` so that what the test is claiming is legible: this is the record clients
    get.
    """
    for entry in merged:
        if entry["domain"] == domain:
            return entry
    return None


def test_the_entries_of_one_name_are_emitted_best_first():
    """Which HOST wins is only half of it: the DNS server answers with the first match.

    Ranking hosts decides which host's entries are in the zone; within them a stopped
    `web-01` listed ahead of a running `web-02` would hand every client the 0.0.0.0
    sentinel, with both records present and nothing in the log.

    Asserted on both branches of the merge: a single host with those two guests, and a
    collision where pve1 wins on its running guest.

    test_a_host_is_ranked_by_its_BEST_entry_rather_than_by_its_first cannot catch this:
    both of the entries competing there carry 0.0.0.0, so any order of them looks alike.
    """
    stopped = _entry("web.lc", "pve1.test", vmid=101, status="stopped",
                     ipv4="0.0.0.0", ipv6="::")
    running = _entry("web.lc", "pve1.test", vmid=102, ipv4="10.0.0.5")

    one_host = app.merge_domains([[stopped, running]])
    assert _first_answer_for(one_host, "web.lc")["ipv4"] == "10.0.0.5", (
        f"web.lc resolves to the stopped guest out of {one_host!r}. The DNS server "
        "answers with the first matching entry, so a running VM is being passed over "
        "for one that is switched off and the name resolves to the 0.0.0.0 sentinel")
    assert len(one_host) == 2, (
        f"the merge kept {one_host!r}: sorting must reorder the entries, not drop one — "
        "the dropped guest's address would leave the zone and its PTR answer with it")

    elsewhere = [_entry("web.lc", "pve2.test", vmid=201, ipv4="10.0.0.9")]
    across_hosts = app.merge_domains([[stopped, running], elsewhere])
    assert _first_answer_for(across_hosts, "web.lc")["ipv4"] == "10.0.0.5", (
        f"web.lc resolves to the stopped guest out of {across_hosts!r}. pve1 won the "
        "collision on the strength of its RUNNING guest and then served its stopped one, "
        "so the collision policy the docstring and the README describe is not what "
        "clients get")


def test_one_address_on_two_hosts_is_reported(caplog):
    """Independent hosts share RFC1918 ranges, and PTR cannot be answered twice.

    Two guests with DIFFERENT names on different hosts may legitimately carry the same
    address, and the merge must not pick between them — both A records are correct.
    But src/dns_server.py answers a PTR by scanning the zone for the address and
    returning the first entry that has it, so one of the two names is unreachable in
    reverse and which one depends on the order the list happens to be in. Nothing else
    in this service can notice that, which is why the warning has to.
    """
    with caplog.at_level("WARNING"):
        merged = app.merge_domains([
            [_entry("one.lc", "pve1.test", vmid=101, ipv4="10.0.0.5")],
            [_entry("two.lc", "pve2.test", vmid=202, ipv4="10.0.0.5")],
        ])

    assert _domains_by_host(merged) == {"one.lc": "pve1.test", "two.lc": "pve2.test"}, (
        "the merge dropped one of them: a shared address is legitimate data and picking "
        "a winner would be guessing at which live guest the operator meant")
    assert len(caplog.records) == 1, (
        f"expected exactly one warning, got {[r.getMessage() for r in caplog.records]}")
    for fragment in ("10.0.0.5", "one.lc", "two.lc", "pve1.test", "pve2.test"):
        assert fragment in caplog.text, (
            f"the warning does not mention {fragment!r}, so it does not say enough to act "
            f"on:\n{caplog.text}")


def test_the_sentinel_addresses_are_not_reported_as_a_shared_address(caplog):
    """0.0.0.0 and :: are on EVERY stopped guest, so counting them would warn constantly.

    They are what src/proxmox.py stores when it could not read an address. Two hosts
    with a switched-off VM each are the ordinary state of a homelab, not an ambiguity.
    """
    with caplog.at_level("WARNING"):
        app.merge_domains([
            [_entry("one.lc", "pve1.test", vmid=101, status="stopped",
                    ipv4="0.0.0.0", ipv6="::")],
            [_entry("two.lc", "pve2.test", vmid=202, status="stopped",
                    ipv4="0.0.0.0", ipv6="::")],
        ])

    assert caplog.records == [], (
        "the sentinels stored for guests with no readable address were reported as a "
        f"shared address: {[r.getMessage() for r in caplog.records]}")


def test_two_guests_at_one_address_on_ONE_host_are_not_reported(caplog):
    """The warning is about an ambiguity that MERGING HOSTS created. This is not one.

    One host reporting two guests at one address is that host's own business — it
    predates the merge, the merge cannot resolve it, and reporting it would put a line
    a minute in the log of anyone whose PVE hands out a duplicate lease.
    """
    with caplog.at_level("WARNING"):
        app.merge_domains([[
            _entry("one.lc", "pve1.test", vmid=101, ipv4="10.0.0.5"),
            _entry("two.lc", "pve1.test", vmid=102, ipv4="10.0.0.5"),
        ]])

    assert caplog.records == [], (
        f"one host's own duplicate address was reported: "
        f"{[r.getMessage() for r in caplog.records]}")


def test_publishing_rebinds_the_zone_rather_than_emptying_it_in_place(monkeypatch):
    """clear() + extend() has a window in it, and N hosts enter that window N times as often.

    src/state.py is read through attribute lookup precisely so a reassignment is
    observed whole. Emptying the list in place instead leaves an interval — short, but
    hit on every single refresh of every single host — in which a DNS query sees no
    domains and answers NXDOMAIN for a name that exists, and NXDOMAIN is cached by
    whoever asked.
    """
    hosts = _isolate_module_state(monkeypatch)
    before = state.servers_list

    app.publish_domains(hosts[0], [_entry("one.lc", "pve1.test")])

    assert state.servers_list is not before, (
        "publishing mutated the list the servers were already reading instead of "
        "swapping in a finished one")


def test_a_host_that_stops_answering_keeps_its_records_and_costs_the_others_nothing(monkeypatch):
    """Failure isolation, which is the whole reason each host owns a slice.

    pve2 goes dark after having published once. Its own names must stay in the zone —
    it is the last thing known to be true about them, and dropping them would break
    resolution for guests that are very probably still running — and pve1 must keep
    refreshing right through it, which is what having its own thread and its own slice
    buys.
    """
    hosts = _isolate_module_state(monkeypatch, ["pve1.test", "pve2.test"])
    # An address each: two hosts sharing one is a different condition with a warning of
    # its own, and this test is not about it.
    app.publish_domains(hosts[0], [_entry("one.lc", "pve1.test", vmid=101, ipv4="10.0.0.5")])
    app.publish_domains(hosts[1], [_entry("two.lc", "pve2.test", vmid=202, ipv4="10.0.0.6")])

    monkeypatch.setattr(app, "build_client", lambda _cfg: object())
    # pve2's API is gone: get_vm_inventory degrades that to None on every tick.
    monkeypatch.setattr(app, "get_vm_inventory", lambda _proxmox, _host: None)
    monkeypatch.setattr(app, "get_domains", _unreachable_get_domains)
    monkeypatch.setattr(app, "time", _FakeClock(ticks=3))

    with pytest.raises(_StopLoop):
        app.update_dns_periodically(hosts[1])

    assert _domains_by_host(state.servers_list) == {
        "one.lc": "pve1.test", "two.lc": "pve2.test"}, (
        f"a host that stopped answering changed the zone: {state.servers_list!r}. Its own "
        "records are the last thing known about guests that are probably still running, "
        "and no other host's records are its business at all")

    # And the host that is still up refreshes into the same merged list, without
    # needing anything from the one that is down.
    app.publish_domains(hosts[0], [_entry("one.lc", "pve1.test", vmid=101, ipv4="10.0.0.9")])
    served = {entry["domain"]: entry["ipv4"] for entry in state.servers_list}
    assert served == {"one.lc": "10.0.0.9", "two.lc": "10.0.0.6"}, (
        f"a live host could not refresh while another was down: {state.servers_list!r}")
