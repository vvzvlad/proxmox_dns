"""Startup, shutdown and multi-host merge invariants of src/app.py.

Thirty-two tests in four groups. Three of the first six — the two startup run() ones
and the updater — defend ONE property, from three directions: whatever the
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

The startup property is easy to lose because the Proxmox side is reached on the
way to those threads at all. It used to be lost in the CONSTRUCTOR: with password
auth proxmoxer posts to /access/ticket from inside ProxmoxAPI(), so build_client()
was itself a network call. Token auth moved that — proxmoxer only stores the token
and assembles a header per request — so the first network call is now
initial_domains(), one per configured host, and that is what these tests put a
failing PVE in front of.

The next three tests are the other end of the process's life: that `docker stop`
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

The third group is the one that had to be written last and should have been written
first: every test above it is satisfied by a SINGLE host, because _isolate_module_state()
installs one by default. Three separate ways of quietly polling only `_hosts[0]` passed
the whole suite. Those tests configure two hosts and assert something only a run over
both of them can produce — an updater per host, a startup fetch that survives the FIRST
host failing and that runs the hosts concurrently rather than in turn, and a `_hosts`
built from every entry of PROXMOX_HOSTS. Two of them are about the host that answers
LATE, on either side of one rule: its answer is published rather than discarded, but
never over something that host's own updater has published in the meantime.

Every test in that group THAT EXERCISES initial_domains() reads state.servers_list, and
none of them reads a return value, because initial_domains() hands nothing back: it
PUBLISHES, and the write inside it is the only path by which the pre-fill reaches the
list the DNS server answers from. The two that do not call it — the updater-per-host one
and the one that counts the HostStates against PROXMOX_HOSTS — are about the wiring
around that call and read nothing of the zone at all. Three of the group are about the
harvest itself: the zone is published even when NO host answers; an answer that reached
its slot is harvested even though its fetch thread has not finished, which is a window a
harvest keyed on the fetch's done Event used to drop the host's answer in altogether;
and a host whose fetch FAILED in time is not also reported as having missed the deadline,
which the harvest can only tell apart because a slot starts at a `pending` sentinel
rather than at the None a failure stores.

The last group is the multi-host merge. The service polls N INDEPENDENT PVE hosts,
each on its own thread and each holding its own last-known slice of the zone, and
merge_domains() is what turns those slices into the one list the DNS server reads.
Five properties are worth pinning there: a name served by two hosts resolves to the
guest that is actually RUNNING; a host that stops answering costs its own freshness
and nothing else — neither its own records nor anybody else's; a name claimed twice
ON ONE HOST is not that collision at all and keeps BOTH entries, because dropping one
takes its address out of the zone and its PTR answer with it; one address arriving
from two hosts is reported rather than resolved, since both A records are right and
only the reverse lookup is ambiguous; and, within a name, the entries come out BEST
FIRST — src/dns_server.py answers with the first match, so choosing the right host and
then listing its stopped guest ahead of its running one serves the 0.0.0.0 sentinel.
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
# The same, for run() coming back after the shutdown Event is set. A regression
# to a bare time.sleep(30) shows up as this bound expiring.
SHUTDOWN_WAIT = 5.0
# How long the startup fetches are given to meet each other at a rendezvous. Only a
# sequential fetch ever spends it: the first call sits here for the whole bound with
# nobody coming to meet it, and the test then fails on the names that went missing
# rather than on the clock.
RENDEZVOUS_WAIT = 5.0
# What "the startup fetch gave up promptly" means, against app.INITIAL_FETCH_DEADLINE.
# It has to be well under that deadline, or a fetch that simply ran the deadline out
# would satisfy it and the test would prove nothing about the shutdown at all.
ABANDON_WAIT = 3.0
# The hard bound on every Event a fake PVE blocks on to stand in for a host that never
# answers. A correct run never reaches it — the test has already made its assertion and
# moved on — so it is not a timing budget but a fuse: a wait with no bound at all leaves
# a wedged thread alive for as long as the interpreter is, and a regression that stops
# the test from releasing it turns into a suite that never finishes rather than one that
# fails. Long enough that a loaded runner cannot reach it by being slow.
BLACK_HOLE_BOUND = 30.0
# How long a startup fetch thread that answered after the deadline is given to publish
# on its own. It is a thread hand-off, not work, so this is slack rather than a budget.
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

    def monotonic(self):
        """The third function src/app.py asks the `time` module for. NOT faked.

        initial_domains() builds its deadline out of it, and a deadline measured on
        the frozen clock above can never expire: `remaining` would stay at its initial
        value for ever, so a fetch that stopped returning would park the wait loop
        permanently and — in the two tests that call run() on the main thread — take
        the whole suite with it. There is no pytest-timeout in this project, so that
        is a hang with nothing to end it.

        The real clock costs these tests nothing: none of them is about the startup
        fetch running out of time, and every fetch they install answers in
        microseconds against a 10 s deadline. What it buys is that a regression here
        FAILS, at INITIAL_FETCH_DEADLINE, instead of hanging.
        """
        return time.monotonic()


class _ClockThatExpiresOnceTheFetchIsParked:
    """`time.monotonic()` for initial_domains(), driven by an Event instead of by a clock.

    The startup wait ends when every fetch has set its done Event or when the deadline
    expires, and one test below needs it to end at a THIRD moment: the instant a fetch
    thread is parked between writing its slot and setting that Event. Reading the real
    clock there would mean choosing a deadline short enough to expire before the fetch
    could reach the window and long enough that a loaded runner could still get there in
    time — a flake whichever way it is rounded.

    So the deadline is expired by the EVENT. monotonic() stands still until the fetch is
    parked, and from then on it ADVANCES BY MORE THAN THE DEADLINE ON EVERY CALL — which
    is what makes it safe rather than merely convenient. initial_domains() builds its
    deadline out of this same clock, so a version that simply jumped to a fixed value
    would leave the deadline unreachable whenever the fetch parked before that line ran,
    and the wait would poll for ever. Advancing every time, the wait gives up on its
    first look at the clock after the window opens, whichever side of the deadline
    computation the parking landed on. It can only ever end the wait, never extend it.

    IT IS ALSO BOUNDED IN REAL TIME, like every other black hole in this file, and that
    is the fuse rather than a budget. The Event is set from inside the substituted lock,
    on a thread recognised by its name, so a change to either could leave it unset for
    ever — and on a clock that never moves the deadline can never expire, which is a wait
    loop that polls for ever. There is no pytest-timeout in this project, so that is a
    hang with nothing to end it. After BLACK_HOLE_BOUND real seconds the clock therefore
    advances regardless of the Event: the wait gives up, the harvest runs without the
    window ever having opened, and the test FAILS on its `assert parked.is_set()` — which
    is what a regression here should do — instead of wedging the suite.
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

    A startup fetch writes its slot INSIDE the lock and sets its done Event in a
    `finally`, AFTER releasing it. This stands in for the lock and holds the fetch thread
    in exactly that gap: the slot is written, the lock is free for the harvest to take,
    and `done` is still unset. Only fetch threads are held — initial_domains() names them
    after the host they fetch, which is what makes them recognisable from in here — so
    the harvest itself passes straight through.

    WHICH release to park on is decided by `answered` rather than by parking on any of
    them. The test's get_domains() sets that Event as it returns, and the slot write is
    the first thing the fetch does under this lock afterwards, so the first release seen
    with it set is the one that carries the slot. Parking on ANY release is right only
    for as long as fetch() takes this lock exactly once: add a read under _publish_lock
    inside ensure_client() or _initial_fetch() and the thread would park BEFORE its slot
    was written, the clock would unfreeze, the harvest would find `pending`, and the test
    would fail with a message blaming a done Event that had nothing to do with it. Only
    the FIRST qualifying release parks, so a fetch that takes the lock again afterwards
    is not held a second time. The test that uses this configures ONE host, so the Event
    is set and read on the same thread and cannot describe some other host's fetch.

    A plain object rather than a Lock subclass: `with` needs nothing but these two
    methods, and wrapping a real Lock keeps the mutual exclusion the production code is
    entitled to while adding the hold on the way out.
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

    TWO places in src/app.py wait on this object, which is why the timeout is
    inspected rather than the call merely counted: the reporting loop waits for
    REPORT_INTERVAL, and initial_domains() waits for INITIAL_FETCH_POLL on every pass
    of its startup wait. Recording any wait at all would make `waited` a claim about
    whichever of the two happened to run — and it would pass on a run() that never
    reached the loop, which is exactly the thing the flag exists to rule out.

    Everything else behaves exactly as threading.Event does.
    """

    def __init__(self):
        super().__init__()
        self.waited = threading.Event()
        # Every timeout seen, so a test that ends up asserting on this can say what
        # it actually observed instead of "the loop was not reached".
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

    monkeypatch restores all of them afterwards, so one test's client cannot leak
    into the next one's ensure_client() and make a retry look like a success —
    and a test that sets the shutdown Event hands the next one a fresh, unset
    Event rather than a process that is already supposed to be stopping.

    The real `_hosts` is built from PROXMOX_HOSTS at import time; replacing it is
    also how a test chooses how many hosts it is exercising. Returns the list, in
    PROXMOX_HOSTS order — which is the order merge_domains() breaks ties in.
    """
    hosts = [_host_state(name) for name in host_names]
    monkeypatch.setattr(app, "_hosts", hosts)
    monkeypatch.setattr(app, "_shutdown", threading.Event())
    monkeypatch.setattr(app, "_shutdown_signal", None)
    # A fresh list rather than the module's own: publish_domains() REBINDS
    # state.servers_list, so a test reads it back through the module rather than
    # holding on to the object it started with.
    monkeypatch.setattr(state, "servers_list", [])
    return hosts


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

    def target(*_args):
        # *_args because the updater target is called with the host it polls, while
        # the two server targets take nothing. One stand-in stands in for both.
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
    """The regression: a client that cannot be built at startup must still leave the zone served.

    Before ensure_client(), run() called build_client() on its first line, and with
    password auth that call authenticated — so a PVE that was down raised straight
    out of run(), before any of the three threads existed. The process died, the
    container restarted, and it died again: `.lc` resolved nowhere for as long as
    PVE was down.

    Token auth means the constructor no longer talks to anything, so what reaches
    ensure_client() now is a configuration fault rather than a dead host. The
    contract it has to keep is the same either way and is what this pins: it
    returns None, and startup carries on.
    """
    dns_started = threading.Event()
    http_started = threading.Event()

    def client_that_cannot_be_built(_cfg):
        raise RuntimeError("No valid authentication credentials were supplied")

    _isolate_module_state(monkeypatch)
    monkeypatch.setattr(app, "build_client", client_that_cannot_be_built)
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

    Being PID 1 is what makes the signal ARRIVE, not what makes it do anything:
    the kernel gives PID 1 no default signal dispositions, so a SIGTERM that PID
    1 has installed no handler for is DROPPED. A process in that state ignores
    the whole grace period and is then SIGKILLed — and since /entrypoint.sh
    `exec`s gosu, python here IS PID 1 and is in exactly that position unless
    run() makes this call. Both signals: SIGTERM is what `docker stop` sends,
    SIGINT is what a foreground `docker run` or a local `make run` sends.
    """
    _isolate_module_state(monkeypatch)
    monkeypatch.setattr(app, "build_client", lambda _cfg: object())
    monkeypatch.setattr(app, "get_domains", lambda _proxmox, _host: [])
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

    def slow_pve_that_is_stopped_mid_fetch(_proxmox, _host):
        # Stands in for the blocking call: the signal arrives while it is out, and
        # the handler has already returned by the time it does.
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
    monkeypatch.setattr(app, "build_client", lambda _cfg: object())
    monkeypatch.setattr(app, "get_domains", lambda _proxmox, _host: [])
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
    # Read back through the module: publish_domains() rebinds state.servers_list, so
    # the list this test started with is not the one the zone is served from.
    assert state.servers_list == domains, (
        f"the zone was not refreshed once PVE answered: {state.servers_list!r}")


# --- Every configured host, not just the first one ------------------------------------
# The group that has to exist because everything above it can be satisfied by ONE host.
# _isolate_module_state() installs a single host by default, so a run() test says nothing
# about the second one — and the three places that walk `_hosts` could each be cut down to
# `_hosts[:1]` without a single test going red. These are written directly against that:
# two hosts configured, and something that only a run over both of them can produce.


def test_run_starts_an_updater_for_every_configured_host(monkeypatch):
    """One thread per host is the entire point of the per-host design.

    A shared loop over the hosts would stall every host behind one that black-holes
    packets, at proxmoxer's 5 s timeout per guest-agent call — which is why each host
    gets a thread of its own. A run() that started only the first host's updater looks
    perfectly healthy: the zone still fills from that host, the servers still bind, and
    every other test in this file still passes. What is gone is every other host's
    refresh, forever.
    """
    hosts = _isolate_module_state(monkeypatch, ["pve1.test", "pve2.test"])
    polled = set()
    all_polled = threading.Event()
    # Never released, exactly like _parked_target(): a target that RETURNS sends
    # start_thread() straight back round its `while True` and spins a core.
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

    The failure is put on the FIRST host deliberately: a fetch that gave up on the
    whole zone the moment one host raised, or one that only ever looked at `_hosts[0]`,
    both produce an empty zone here while a merge over one host produces the same
    answer as before.

    Read back through state.servers_list, like every other test in this group:
    initial_domains() returns nothing, and that list is the zone the DNS server answers
    from. Asserting on a return value would leave the publish itself untested.
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

    initial_domains() runs before the DNS socket is bound, so its duration IS an
    outage of the whole `.lc` zone. Sequentially, several dead hosts cost the SUM of
    their timeouts; concurrently they cost the slowest one, and the deadline caps even
    that.

    The rendezvous is what makes the claim testable without measuring a clock: each
    fetch only returns once EVERY host is inside the fetch at the same moment. A
    sequential loop can never assemble that — the first call waits out RENDEZVOUS_WAIT
    alone, breaks the barrier, and the rest raise on it immediately — so both hosts
    lose their names and the assertion below reports it as missing names rather than
    as a timing flake.
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

    The container is on its way down and the grace period is already running. Waiting
    out INITIAL_FETCH_DEADLINE for a host that will never answer spends that budget on
    a startup which is about to be thrown away — and what is at the end of the budget
    is a SIGKILL on exit 137.

    pve2 here never answers at all; only the wait noticing the flag can end this call
    early. The bound is measured against real time on purpose: this is a claim about
    wall clock, and a fake clock would let the very regression it guards pass.

    initial_domains() RUNS ON A DAEMON THREAD, for the reason _run_on_a_worker_thread()
    gives about run(). A regression to a sequential fetch — the obvious way to lose this
    property — leaves the call blocked on pve2 for ever, and on the main thread that is
    not a failing test but a suite that never finishes: nothing here would be left to
    fail it, and pytest-timeout is not a dependency. On a worker thread the same
    regression is the bounded wait below expiring with a message. The black hole is
    bounded too, as a second line of defence: no correct run ever reaches the end of it.
    """
    _isolate_module_state(monkeypatch, ["pve1.test", "pve2.test"])
    monkeypatch.setattr(app, "build_client", lambda _cfg: object())
    # Never set by anything. The bound is what keeps a stuck fetch thread from
    # outliving the test run itself; a daemon thread parked on it costs nothing.
    black_hole = threading.Event()

    def pve2_never_answers(_proxmox, host):
        if host == "pve2.test":
            black_hole.wait(BLACK_HOLE_BOUND)
        return [_entry("one.lc", "pve1.test", vmid=101)]

    monkeypatch.setattr(app, "get_domains", pve2_never_answers)
    # The stop is already recorded when the fetch begins, which is the same state the
    # process is in a moment after a SIGTERM lands mid-fetch: the handler has returned
    # and the Event is set while the fetch is still out.
    app._shutdown.set()
    zone_before_the_fetch = state.servers_list

    returned = threading.Event()

    def call_initial_domains():
        app.initial_domains()
        returned.set()

    threading.Thread(target=call_initial_domains, daemon=True).start()

    # The wait IS the measurement: it comes back as soon as the fetch returns, and
    # expires if the fetch is still going — so the clock is read the same way either
    # way, without the test having to hold the call on its own thread to time it.
    assert returned.wait(ABANDON_WAIT), (
        f"the startup fetch was still going {ABANDON_WAIT} s after being started with "
        f"the shutdown flag already set. It is waiting out its own "
        f"{app.INITIAL_FETCH_DEADLINE} s deadline — or one host's answer — on a startup "
        "that is being abandoned, and every second of it comes out of the container's "
        "stop_grace_period")

    # Abandoning the WAIT is not abandoning the PUBLISH: whatever arrived before the flag
    # was noticed is still assembled and written to the zone, so a stop that turns out not
    # to be one — the signal handler is installed before the fetch, and run() decides what
    # to do about it afterwards — leaves the DNS server with the names that did answer.
    # The rebind is the whole claim; WHICH host's names got in is a race with the shutdown
    # by construction and is not something to assert on.
    assert state.servers_list is not zone_before_the_fetch, (
        "the startup fetch gave up its wait and published nothing at all: "
        "state.servers_list still holds the object it held before the fetch ran. The "
        "write inside initial_domains() is the only path the pre-fill has into the zone")

    # The claim is made; now let the parked fetch finish INSIDE this test rather than
    # leaving it to wake up in the middle of another one. See _join_the_startup_fetch_of.
    black_hole.set()
    _join_the_startup_fetch_of("pve2.test")


def _join_the_startup_fetch_of(host_name):
    """Wait, BOUNDED, for one host's startup-fetch thread to finish.

    initial_domains() names those threads after the host they fetch, which is what makes
    them findable from here — and joining one is the difference between asserting on
    what a late fetch did and polling until it probably has. A thread that has already
    finished is not in the enumeration any more; that is a pass, not a miss.

    EVERY TEST THAT PARKS A FETCH THREAD MUST RELEASE IT AND JOIN IT HERE before it
    ends, and not only out of tidiness. A parked fetch is a straggler by construction,
    so when it finally wakes it takes the late-publish path — and by then monkeypatch
    has put the real `_hosts` and the real `state.servers_list` back, so the write lands
    in the module state of whatever test is running at that moment. It would also be
    found by this helper under the name the next test is looking for.
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

    The deadline exists to stop a slow host from holding the DNS socket, and it does
    that by binding without it. Discarding the answer when it does arrive is a separate
    decision and a bad one: a host with forty or fifty guests can genuinely miss the
    deadline, and its names would then wait for a whole second full walk by its own
    updater — roughly doubling time-to-zone for exactly the hosts the pre-fill exists
    for.

    pve2 is held past a deliberately tiny deadline and released afterwards, so the
    publish under test is unambiguously the LATE path: initial_domains() has already
    returned a zone without it.
    """
    _isolate_module_state(monkeypatch, ["pve1.test", "pve2.test"])
    monkeypatch.setattr(app, "build_client", lambda _cfg: object())
    # Short enough that the test can outlast it without waiting on anything real. The
    # value is not what is under test — that a missed deadline is survivable is — so
    # shrinking it costs nothing and keeps the suite off a ten-second wait.
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

    By the time a late fetch answers, that host's updater thread is running and may
    already have published something newer. The late answer was built before the sockets
    were bound, so letting it through then would put a stale address into the zone and
    leave it there until the next refresh — the exact failure the discard used to
    prevent, which is why the late path is conditional rather than unconditional.
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
    # pve2's own updater gets there first — which is precisely the case the deadline
    # hands the slice over for.
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

    initial_domains() returns nothing and run() assigns nothing, so the one line inside
    it that rebinds state.servers_list is the ONLY path by which the pre-fill reaches the
    list the DNS server answers from. Deleting that line leaves every per-host slice
    correct, every merge correct, and the zone empty — a regression that no assertion on
    a returned list can see, and one whose cost is written on the function itself: the
    DNS server binds and answers NXDOMAIN for real names until the first poll lands,
    while whoever asked caches the negative answer.

    Every host fails here, so what gets published is an EMPTY zone, and the claim is the
    publish rather than its contents: merge_domains() always builds a new list, so the
    rebind is what tells an assignment that happened from one that never did. Empty is
    also the case where the write is easiest to think unnecessary, which is exactly why
    it is the one pinned.
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

    A fetch thread writes its slot INSIDE _publish_lock and sets its done Event in a
    `finally`, AFTER the lock is released. In between, the slot is filled and the answer
    is on time — the fetch computed `on_time = True`, so it will publish nothing itself —
    while `done` still says the host has not answered. A harvest that ALSO required
    `done` skipped that slot, and the host's answer was then published by neither side:
    its names were NXDOMAIN until its own updater's first successful poll, with every
    asker caching that in the meantime. It is the one failure of this machinery that
    costs a host its whole slice.

    The window is opened deliberately rather than waited for. The substituted lock holds
    the fetch thread on its way out of the release that carries the slot write — slot
    written, lock free, `done` unset — and the substituted clock expires the deadline at
    that exact moment, so the harvest runs inside the window on every run of this test
    rather than on the unlucky ones. Neither stand-in changes what src/app.py does; they
    only decide when the two threads meet.
    """
    _isolate_module_state(monkeypatch, ["pve1.test"])
    parked = threading.Event()
    proceed = threading.Event()
    # Set as the fetch's answer comes back, which is what lets the lock double tell the
    # release that carries the slot write from any release taken on the way TO an answer.
    # See _LockThatParksAFetchOnItsWayOut.
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

    # Released and joined before anything is asserted, so a failure below does not leave
    # a fetch thread parked into whatever test runs next. See _join_the_startup_fetch_of.
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


def test_a_host_whose_fetch_failed_in_time_is_not_named_in_the_deadline_warning(
        monkeypatch, caplog):
    """A FAILURE IS NOT A MISSED DEADLINE, and the slots are the only thing telling them apart.

    A slot starts as a `pending` sentinel rather than as None, because None is what a
    fetch that RAN AND FAILED stores in it. Collapse the two — `slots = [None] * len(_hosts)`
    with a harvest keyed on `domains is None`, or a harvest that tests the slot for truth
    instead of `is pending` — and everything about the zone stays correct while a host that
    answered in 200 ms is ALSO reported as having gone quiet for INITIAL_FETCH_DEADLINE
    seconds.

    The cost is paid by whoever reads the log. A revoked token, or one the privsep step in
    the README never gave an ACL to, fails fast and says so in an ERROR of its own. Stacking
    "no answer within 10 s" on top of that line contradicts it, and the false half is the
    one that points at the network and at timeouts rather than at the ACL the true half
    names.

    pve1 fails at once and well inside the deadline; pve2 answers normally. Nothing here is
    late, so the warning must not be produced at all.
    """
    _isolate_module_state(monkeypatch, ["pve1.test", "pve2.test"])
    monkeypatch.setattr(app, "build_client", lambda _cfg: object())

    def pve1_says_at_once_that_its_token_is_no_good(_proxmox, host):
        if host == "pve1.test":
            raise RuntimeError("authentication failure: no ACL for dns@pve")
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

    Nothing else in this file can see this: every other test replaces `_hosts` with
    states of its own making, so a `_hosts` built from `settings.proxmox_hosts[:1]`
    would leave the whole suite green and the deployment polling one of its hosts.
    tests/conftest.py configures two on purpose, which is what makes the comparison
    below worth making.
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
    """The regression guard. A duplicate within one host is not a cross-host collision.

    The domain is the VM name's first segment, so `web-01` and `web-02` ON THE SAME
    HOST both produce `web.lc`. That predates the multi-host work entirely and both
    entries have always been in the list. A merge that dedupes by domain alone collapses
    them, and what goes with the dropped entry is its ADDRESS: src/dns_server.py answers
    a PTR by scanning the list for the address, so that guest's reverse lookup starts
    answering NXDOMAIN, and the status page loses its row too.
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
    """Once a minute, forever, about something no operator was asked to change.

    The merge runs on every rebuild, so a WARNING here is a line per host per refresh
    for as long as both guests exist — and the text of it named the same host on both
    sides of a "collision between hosts". The fact is still recorded, at a level whose
    job is exactly this.
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

    Ranking hosts puts the right host's entries in the zone and stops there. Within them
    the order was whatever Proxmox listed, so a stopped `web-01` sitting ahead of a
    running `web-02` handed every client the 0.0.0.0 sentinel — a healthy, reachable
    guest dropped in favour of one that is switched off, with both records present and
    nothing in the log.

    Asserted on BOTH branches of the merge. The single-host one is not a multi-host bug
    at all: one host with those two guests has always answered that way, and the sort
    fixes it here for the first time. The collision branch is the case the reviewer
    reproduced — pve1 wins the name on the strength of its running guest and then serves
    its stopped one.

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
