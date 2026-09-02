"""Startup and shutdown invariants of src/app.py.

Six tests in two groups. Three of them — the two startup run() ones and the
updater at the bottom — defend ONE property, from three directions: whatever the
Proxmox side does while the process is starting, the DNS and HTTP servers still
come up. This service answers DNS for the whole internal `.lc` zone, so a startup
that dies before those two threads exist does not degrade the zone — it removes
it, and because docker restarts the container it does so in a loop.

The restart policy is `always` rather than `unless-stopped`, and that is a
behavioural choice, not a spelling. The two differ in one case: a container an
operator stopped ON PURPOSE. `unless-stopped` remembers that stop across a
restart of the docker daemon and leaves it down; `always` brings it back by
itself. For the authoritative server of the `.lc` zone that is what is wanted —
a rebooted host must resolve names again unattended — at the accepted price that
a deliberate stop only holds until the daemon next restarts. The full note is on
ensure_client() in src/app.py.

The startup property is easy to lose because proxmoxer authenticates EAGERLY:
ProxmoxAPI builds a ProxmoxHTTPAuth, whose __init__ posts to /access/ticket. So
`build_client()` is a network call, and a PVE that is down or rejecting
credentials raises out of the constructor, not out of the first request.

The other three tests are the other end of the process's life: that `docker stop`
actually stops it — the handler is installed, a stop that lands during startup is
acted on before anything binds, and the reporting loop returns the moment the
handler fires. In the container python is PID 1, and PID 1 is given NO
default signal dispositions by the kernel — an unhandled SIGTERM there is
dropped rather than applied. A container in that state does not go dark: it
keeps answering `.lc` queries right through the grace period and is then
SIGKILLed on exit 137. What that costs is the redeploy rather than the zone —
every `docker stop` sits out the whole 45 s this stack allows (see
`stop_grace_period` in docker-compose.yml; docker's own default is 10 s) and
ends in a kill instead of a clean exit. The handler and the interruptible wait
are what turn that into a stop answered in milliseconds.
"""

import signal
import threading

import pytest

from src import app, state

# How long to wait for a server thread to report in. Generous: it only has to
# cover thread scheduling, and a failing run pays this once.
STARTUP_WAIT = 5.0
# The same, for run() coming back after the shutdown Event is set. A regression
# to a bare time.sleep(30) shows up as this bound expiring.
SHUTDOWN_WAIT = 5.0


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

    Derived from BaseException RATHER THAN Exception on purpose: start_thread()
    catches Exception to restart a crashed server, so a normal exception would be
    swallowed and the thread would immediately spin the loop again. BaseException
    passes through it and lets a test end the loop it is driving.
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


class _RecordingEvent(threading.Event):
    """A shutdown Event that says whether run()'s loop ever WAITED on it.

    `while not _shutdown.wait(REPORT_INTERVAL)` is the only wait() on this object
    in src/app.py, so a set `waited` means the reporting loop was entered — the
    one thing a test about that loop cannot infer from run() having returned,
    since run() also returns from the early check above the loop without ever
    touching it. Everything else behaves exactly as threading.Event does.
    """

    def __init__(self):
        super().__init__()
        self.waited = threading.Event()

    def wait(self, timeout=None):
        self.waited.set()
        return super().wait(timeout)


def _isolate_module_state(monkeypatch):
    """Reset the client cache, the zone and the shutdown flag src/app.py keeps at module level.

    monkeypatch restores all of them afterwards, so one test's client cannot leak
    into the next one's ensure_client() and make a retry look like a success —
    and a test that sets the shutdown Event hands the next one a fresh, unset
    Event rather than a process that is already supposed to be stopping.
    """
    monkeypatch.setattr(app, "_proxmox", None)
    monkeypatch.setattr(app, "_client_error_logged", False)
    monkeypatch.setattr(app, "_shutdown", threading.Event())
    monkeypatch.setattr(app, "_shutdown_signal", None)
    servers = []
    monkeypatch.setattr(state, "servers_list", servers)
    return servers


def _parked_target(reported=None, then_stop=False):
    """A stand-in for one of the three loops run() hands to a thread.

    Sets `reported` if given, then blocks forever — which is what the real
    targets do, since the UDP loop, serve_forever() and the updater's `while
    True` never return. Returning instead would send start_thread() straight back
    round its own `while True` and spin the CPU. The thread is a daemon parked on
    an Event, so it costs nothing and dies with the interpreter.

    The updater gets one of these too, in ALL FIVE of the run() tests below —
    none of them is about the updater, which has its own test at the bottom of
    this file. In the four that install a _FakeClock, letting the real updater
    run would put that clock on a second thread, where its _StopLoop would
    surface as an unhandled exception in a thread rather than as anything the
    test asserts. The fifth — the main-loop one — never patches `app.time` at
    all, and there the parking is simpler than that: it keeps the real updater,
    with its real sleeps and its real calls to PVE, from running.

    `then_stop` sets the module's shutdown Event once this target is reached, and
    it is how the run() tests below get run() to come back instead of sitting in
    its reporting loop. Asking for the stop from INSIDE a thread run() started is
    the only way to say "the stop arrived AFTER startup". Setting the Event before
    calling run() would say something else entirely — a stop that arrived DURING
    startup, which run() now answers by returning before it binds anything — and
    those tests would then be green or red on a branch that is not the one they
    are about. `app._shutdown` is looked up at call time because
    _isolate_module_state() has replaced it with a fresh Event.
    """
    parked = threading.Event()

    def target():
        if reported is not None:
            reported.set()
        if then_stop:
            app._shutdown.set()
        parked.wait()

    return target


def _run_on_a_worker_thread():
    """Start run() on a daemon thread and hand back the Event that says it returned.

    NO TEST IN THIS FILE MAY CALL run() ON THE MAIN THREAD WHILE ITS REPORTING LOOP
    IS REACHABLE. That loop is `while not _shutdown.wait(REPORT_INTERVAL)`, and the
    only thing that ends it is the Event being set from one of the threads run()
    started. When that signal does not arrive — the thread was never started, the
    startup order moved, the target raised and start_thread() swallowed it — the
    loop simply waits again, forever, and a main-thread call takes the whole suite
    with it. There is no timeout anywhere on that path and pytest-timeout is not a
    dependency of this project.

    On a DAEMON thread the same failure is bounded by construction: the test keeps
    the main thread, every claim it makes is an Event wait with a deadline on it,
    and the worker dies with the interpreter whether or not it ever came back. The
    price is that run() cannot install signal handlers there — signal.signal()
    raises ValueError off the main thread, which install_signal_handlers() catches
    and warns about — so a test using this helper says nothing about handlers and
    needs no fixture to undo one. Two tests still call run() DIRECTLY, and only one
    of them has to: the handler test reads signal.getsignal() afterwards, a claim
    that can only be made where signal.signal() was allowed to work. The other —
    the one about a stop that arrived during startup — asserts only that three
    targets are never reached, which a worker thread would show just as well; it
    takes saved_signal_handlers to undo the handlers run() installs on its way past,
    not because the handlers are what it is about. Both set the shutdown Event
    before run() gets past initial_domains(), so run() there leaves by its early
    return and the loop above is never reached at all.
    """
    returned = threading.Event()

    def call_run():
        app.run()
        returned.set()

    threading.Thread(target=call_run, daemon=True).start()
    return returned


def test_run_starts_dns_and_http_when_the_proxmox_client_cannot_be_built(monkeypatch):
    """The regression: an unreachable PVE at startup must still leave the zone served.

    Before ensure_client(), run() called build_client() on its first line, so the
    eager authentication above raised straight out of run() — before any of the
    three threads existed. The process died, the container restarted, and it died
    again: `.lc` resolved nowhere for as long as PVE was down.
    """
    dns_started = threading.Event()
    http_started = threading.Event()

    def unreachable_pve():
        raise ConnectionError("connection refused: /access/ticket")

    _isolate_module_state(monkeypatch)
    monkeypatch.setattr(app, "build_client", unreachable_pve)
    monkeypatch.setattr(app, "start_dns_server", _parked_target(dns_started))
    # The stop is asked for from inside the LAST thread run() starts, so the first
    # wait() in run()'s reporting loop returns at once and run() comes back
    # instead of blocking for REPORT_INTERVAL. It has to arrive from there rather
    # than before the call: a stop already pending when run() begins is a
    # different case, which run() answers by returning before it starts anything.
    # See _parked_target(). _isolate_module_state() put a fresh Event on the
    # module, so this cannot leak into another test.
    monkeypatch.setattr(app, "start_http_server",
                        _parked_target(http_started, then_stop=True))
    monkeypatch.setattr(app, "update_dns_periodically", _parked_target())
    # A clock that refuses to sleep, kept as a WATCHDOG rather than as the thing
    # driving the test: run()'s reporting loop waits on the Event now and must
    # never sleep again. A loop mutated back to time.sleep() raises _StopLoop out
    # of run() on the worker thread rather than napping, so `returned` below is
    # never set and the last assertion says so at SHUTDOWN_WAIT instead of the
    # test sitting through a 30 s sleep per pass. It is a second line only: the
    # bounded waits are what make this test unable to hang at all.
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

    get_domains() degrades an unreachable API to None, but only for the two
    exception types it catches. proxmoxer's AuthenticationError derives from plain
    Exception and is neither of them, so it reaches run() — which is why
    initial_domains() guards the call rather than trusting it.
    """
    dns_started = threading.Event()
    http_started = threading.Event()

    def rejected_credentials(_proxmox):
        raise RuntimeError("Couldn't authenticate user: dns@pve")

    _isolate_module_state(monkeypatch)
    monkeypatch.setattr(app, "build_client", lambda: object())
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

    Being PID 1 is what makes the signal ARRIVE, not what makes it do anything:
    the kernel gives PID 1 no default signal dispositions, so a SIGTERM that PID
    1 has installed no handler for is DROPPED. A process in that state ignores
    the whole grace period and is then SIGKILLed — and since /entrypoint.sh
    `exec`s gosu, python here IS PID 1 and is in exactly that position unless
    run() makes this call. Both signals: SIGTERM is what `docker stop` sends,
    SIGINT is what a foreground `docker run` or a local `make run` sends.
    """
    _isolate_module_state(monkeypatch)
    monkeypatch.setattr(app, "build_client", lambda: object())
    monkeypatch.setattr(app, "get_domains", lambda _proxmox: [])
    monkeypatch.setattr(app, "start_dns_server", _parked_target())
    monkeypatch.setattr(app, "start_http_server", _parked_target())
    monkeypatch.setattr(app, "update_dns_periodically", _parked_target())
    # Pre-set here, unlike the two tests above, and deliberately so: it makes run()
    # leave by its early-return path, which is the shortest way to the one thing
    # this test asks. The handlers go on BEFORE anything that can block, so they
    # are installed on that path too — and if they ever stopped being first, this
    # test is what says so.
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

    Installing a handler makes the signal RECORDED, not acted on: under PEP 475
    CPython resumes the interrupted syscall once the handler returns, so a SIGTERM
    landing while initial_domains() waits on an unreachable PVE does nothing until
    that call comes back. What happens next is what this pins. Without the check
    run() would go on to bind :53 and :80, log a start, and tear the lot down on
    its first wait() — and every one of those steps is time charged against the
    stop_grace_period the stop is already spending. Under docker's 10 s default,
    with proxmoxer's 5 s timeout on each per-VM guest-agent call, that margin is
    what decides between exit 0 and a SIGKILL on exit 137.

    The three targets are stand-ins that would report in if they were reached; the
    point of the test is that none of them is.
    """
    dns_started = threading.Event()
    http_started = threading.Event()
    updater_started = threading.Event()

    def slow_pve_that_is_stopped_mid_fetch(_proxmox):
        # Stands in for the blocking call: the signal arrives while it is out, and
        # the handler has already returned by the time it does.
        app._shutdown.set()
        return []

    _isolate_module_state(monkeypatch)
    monkeypatch.setattr(app, "build_client", lambda: object())
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

    run() goes on a WORKER thread, through _run_on_a_worker_thread() like the two
    startup tests above — see that helper for why nothing here may call run() on
    the main thread. Nothing joins that worker: it is a daemon, and what catches a
    regression to a bare `time.sleep(30)` is `returned.wait(SHUTDOWN_WAIT)` below
    expiring with a message, rather than a suite that hangs for half a minute and
    then forever.

    THE STOP HAS TO ARRIVE AFTER STARTUP, and that is not a detail. run() returns
    early — before it binds anything, before the loop exists — when the Event is
    already set on entry. Thread.start() comes back long before the worker is
    through install_signal_handlers() and initial_domains(), so asking for the
    stop right after it reaches that early return every time: the loop this test
    is named after is never entered, and a loop mutated back to time.sleep() sails
    through. So the last thread run() starts reports in, and only then is the
    shutdown requested — by which point run() is provably past the early return,
    with nothing left ahead of it but the loop.

    request_shutdown() is called directly, exactly as the kernel would call it,
    instead of raising a real signal: a real SIGTERM in a process where the
    handler had gone missing would kill the pytest run itself rather than report
    a failure.
    """
    _isolate_module_state(monkeypatch)
    # A shutdown Event that records the loop WAITING on it, so "run() came back"
    # and "run() came back out of the loop" are two separate claims. Without it a
    # run() that returned from the early return above would satisfy the assertion
    # below just as well, which is precisely how this test used to pass while
    # testing nothing. Installed after _isolate_module_state(), which puts a plain
    # Event there.
    shutdown = _RecordingEvent()
    monkeypatch.setattr(app, "_shutdown", shutdown)
    monkeypatch.setattr(app, "build_client", lambda: object())
    monkeypatch.setattr(app, "get_domains", lambda _proxmox: [])
    monkeypatch.setattr(app, "start_dns_server", _parked_target())
    # The LAST of the three threads run() starts, and the one that reports startup
    # is complete. `then_stop` stays off on purpose: this test wants the stop to
    # come from OUTSIDE, at a moment it chooses, not from inside the thread.
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
        "run() returned without ever waiting on the shutdown Event, so it left by "
        "some path other than the loop and this test proved nothing about the "
        "loop. A loop that sleeps instead of waiting looks exactly like this")
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
    domains = [{"domain": "foo.lc", "ipv4": "10.0.0.5", "ipv6": "fe80::1"}]

    def pve_up_on_the_third_try():
        attempts.append(None)
        if len(attempts) < 3:
            raise ConnectionError("connection refused: /access/ticket")
        return client

    def inventory(proxmox):
        assert proxmox is client, "the updater polled with something other than the built client"
        return frozenset({(100, "foo-bar", "node1", "running")})

    def all_domains(proxmox):
        assert proxmox is client, "the updater fetched with something other than the built client"
        return list(domains)

    servers = _isolate_module_state(monkeypatch)
    monkeypatch.setattr(app, "build_client", pve_up_on_the_third_try)
    monkeypatch.setattr(app, "get_vm_inventory", inventory)
    monkeypatch.setattr(app, "get_domains", all_domains)
    # Four ticks: two that find PVE down, one that connects and refreshes, and a
    # fourth that must reuse the client. The fifth sleep ends the loop.
    monkeypatch.setattr(app, "time", _FakeClock(ticks=4))

    with pytest.raises(_StopLoop):
        app.update_dns_periodically()

    assert len(attempts) == 3, (
        f"expected two failed builds and one that took, got {len(attempts)} attempts: "
        "either the updater gave up after the first failure, or it rebuilds the client "
        "on every tick instead of caching it")
    assert servers == domains, (
        f"the zone was not refreshed once PVE answered: {servers!r}")
