"""What src/proxmox.py has to hand back for the merge to work, and the silent failures.

Three things are pinned here.

EVERY entry carries where it came from. `host`, `vmid` and `status` are what
src/app.py's merge ranks a collision on, and get_vm_ip() returns from four places —
the stopped guest, the successful read, and two except branches. An entry that lost
`status` on one of those paths cannot be ranked as running and would quietly lose a
collision it should have won, which is the sort of bug that shows up as one VM being
unreachable by name and nothing in the log at all.

AND A HOST THAT LISTS NODES BUT NOT ONE GUEST IS REPORTED. An API token defaults to
privilege separation, so a token without an ACL of its own authenticates perfectly — and
still gets the full node list back, because the node index is served without permission
filtering. Only the guest listings come back empty: no error, no exception, nothing to
notice, and the zone just loses that host's names. The warning fires on that shape —
nodes present, zero guests LISTED, every listing having answered — and is the only thing
standing between it and a silent outage. What it must NOT fire on is pinned just as
hard: a host whose guests are all templates, a host whose every node failed, and a host
whose one node handed back something with no length at all, all reach zero guests for
reasons that have nothing to do with permissions. A host where SOME node failed and the
rest listed nothing does fire — the node that never answered says nothing about the ones
that did — and the failed node is named in the line, in the singular when there is one
of it.

A HOST THAT ANSWERS THE NODE INDEX EMPTY IS REPORTED TOO, through the same throttle and
the same constant, but under its own key: it is a different fault with a different fix —
an address that does not point at a PVE, rather than a token without an ACL — so the two
lines must not silence each other.

BOTH ARE THROTTLED TO ONCE AN HOUR PER HOST, and both halves of that are pinned below.
get_domains runs on every full refresh, and "full refresh" has a 2-second floor rather
than a one-minute period: update_dns_periodically() in src/app.py refreshes whenever the
cheap inventory reading it takes every `detect_interval` (2 s) CHANGED, as well as once
`full_refresh_interval` (60 s) has elapsed. A host with no QEMU guests at all is a
legitimate configuration, so an unthrottled line is noise; an hourly line still repeats,
which a one-shot would not, and a one-shot that latched would go silent forever. The
throttle is UNCONDITIONAL — no recovery clears it early, which is pinned below too,
because the condition that fires each warning and any recovery reset for it are exact
complements: with the reset in place a flapping host drew a line on every single
transition and the interval never applied at all.

AND A PARTIAL ANSWER IS STILL AN ANSWER, which is the behaviour rather than the ideal.
On a multi-node cluster one node's guest list can fail while the others succeed, and
what comes back is a list short by that node's guests, indistinguishable from a complete
one. The test below pins that as it stands — it predates multi-host support and this
change deliberately left it alone — so that whoever changes it does so knowingly and not
by accident. Only the NODE LISTING failing gives back None, the caller's "keep the slice
you have" signal.
"""

from src import proxmox


class _Clock:
    """Stands in for the `time` module inside src/proxmox, so the throttle can be aged.

    Patched onto src.proxmox rather than onto stdlib `time`, so nothing outside the
    module under test ever sees a moved clock.
    """

    def __init__(self, now=0.0):
        self.now = now

    def monotonic(self):
        return self.now


class _Agent:
    """The `agent("network-get-interfaces")` endpoint: answers, or raises what it was given."""

    def __init__(self, result):
        self._result = result

    def get(self):
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


class _Qemu:
    """`proxmox.nodes(node).qemu` — a list when called on, one guest when called with a vmid."""

    def __init__(self, vms, agent_result):
        self._vms = vms
        self._agent_result = agent_result

    def get(self):
        return self._vms

    def __call__(self, _vmid):
        return self

    def agent(self, _endpoint):
        return _Agent(self._agent_result)


class _BrokenQemu:
    """One node whose guest list fails, while the rest of the cluster answers."""

    def __init__(self, error):
        self._error = error

    def get(self):
        raise self._error


class _UnenumerableQemu:
    """A node whose guest listing answers without raising, and has no length.

    proxmoxer hands back the endpoint's `data` field as-is, so a malformed answer —
    `{"data": null}` — reaches the walk as None and breaks only when it is counted.
    """

    def get(self):
        return None


class _Node:
    def __init__(self, qemu):
        self.qemu = qemu


class _Nodes:
    """`proxmox.nodes` — a list when called on, one node when called with a name."""

    def __init__(self, nodes, node):
        self._nodes = nodes
        self._node = node

    def get(self):
        return self._nodes

    def __call__(self, _name):
        return self._node


class _NodesByName(_Nodes):
    """The same, for a cluster where the nodes have to answer differently from each other."""

    def __init__(self, nodes, by_name):
        super().__init__(nodes, None)
        self._by_name = by_name

    def __call__(self, name):
        return self._by_name[name]


class _Proxmox:
    def __init__(self, nodes, vms=(), agent_result=None):
        self.nodes = _Nodes(list(nodes), _Node(_Qemu(list(vms), agent_result)))


class _Cluster:
    """A host of several nodes, each with its own qemu endpoint."""

    def __init__(self, by_name):
        self.nodes = _NodesByName([{"node": name} for name in by_name], by_name)


ONE_NODE = [{"node": "pve"}]
RUNNING_VM = {"vmid": 100, "name": "foo-bar", "status": "running"}
OTHER_VM = {"vmid": 200, "name": "bar-baz", "status": "running"}
STOPPED_VM = {"vmid": 101, "name": "baz-qux", "status": "stopped"}
TEMPLATE_VM = {"vmid": 900, "name": "tmpl-deb12", "status": "stopped", "template": 1}
AGENT_ANSWER = {"result": [{"name": "eth0", "ip-addresses": [
    {"ip-address-type": "ipv4", "ip-address": "10.0.0.5"}]}]}


def test_an_empty_node_list_is_reported_rather_than_served_silently(caplog):
    """A host that answers the node index with nothing, which a healthy PVE never does.

    This is NOT the missing token ACL, however much it looks like it: `/nodes` is served
    without permission filtering, so even a token with no ACL at all gets the full node
    list back — measured on PVE 9.2.10. Handing out the `pveum acl modify` advice here
    would send whoever hits this off after the wrong cause, so that advice belongs to the
    warning below and must not appear in this one.

    The empty result is still returned — a host that genuinely has no VMs is a
    legitimate configuration, and keeping its old records forever would mean answering
    with addresses of guests that no longer exist. So the log line is the whole of the
    signal, and it has to name the host.
    """
    with caplog.at_level("WARNING"):
        domains = proxmox.get_domains(_Proxmox(nodes=[]), "pve1.test")

    assert domains == [], "an empty host must publish an empty slice, not None"
    assert len(caplog.records) == 1, (
        f"expected one warning, got {[r.getMessage() for r in caplog.records]}")
    assert "pve1.test" in caplog.text, "the warning does not say which host answered empty"
    assert "NO nodes" in caplog.text, (
        f"the warning does not say what actually happened — that the node index came back "
        f"empty:\n{caplog.text}")
    assert "pveum" not in caplog.text, (
        "this warning blames the token's missing ACL, and a token without one still gets "
        f"the full node list: the node index is not permission-filtered:\n{caplog.text}")


def test_the_empty_node_index_warning_is_throttled_hourly_too(monkeypatch, caplog):
    """The node-index line goes through the same throttle as the no-guests one.

    An address that does not point at a PVE is a standing configuration mistake, not a
    transient, so this fires on every full refresh — as often as every couple of seconds —
    for the life of the process unless something holds it back. It has to REPEAT, for the
    same reason the no-guests line does: whoever comes looking after the fact needs to find
    it. So: one line, then silence, then a line again once the interval has passed.

    Logging this one straight through `logger.warning` instead of the throttle is a
    one-word edit and nothing else in the suite notices it.
    """
    clock = _Clock()
    monkeypatch.setattr(proxmox, "time", clock)
    api = _Proxmox(nodes=[])

    with caplog.at_level("WARNING"):
        proxmox.get_domains(api, "pve1.test")
        first = [record.getMessage() for record in caplog.records]
        caplog.clear()

        proxmox.get_domains(api, "pve1.test")
        immediately_after = [record.getMessage() for record in caplog.records]
        caplog.clear()

        clock.now += proxmox._WARNING_INTERVAL + 1
        proxmox.get_domains(api, "pve1.test")
        an_hour_later = [record.getMessage() for record in caplog.records]

    assert len(first) == 1, f"expected one warning, got {first}"
    assert "NO nodes" in first[0], f"the wrong warning fired: {first[0]}"
    assert immediately_after == [], (
        f"the node-index warning repeated on the very next refresh: {immediately_after}\n"
        "It is not throttled at all, so a host pointed at the wrong address fills the log "
        "for as long as it stays pointed there")
    assert len(an_hour_later) == 1, (
        f"the interval passed and the node-index warning did not come back: {an_hour_later}")


def test_the_empty_node_index_throttle_is_kept_per_host(monkeypatch, caplog):
    """Two hosts pointed at nothing are two mistakes to fix, so two lines.

    The same regression as for the no-guests throttle, on the other key: a timer keyed on
    anything less than the host lets the first host to warn hide every other host's for an
    hour. With one host name in play a constant key is indistinguishable from a
    per-host one, which is why tests/conftest.py configures two.
    """
    clock = _Clock()
    monkeypatch.setattr(proxmox, "time", clock)
    api = _Proxmox(nodes=[])

    with caplog.at_level("WARNING"):
        proxmox.get_domains(api, "pve1.test")
        proxmox.get_domains(api, "pve2.test")
        both = [record.getMessage() for record in caplog.records]
        caplog.clear()

        proxmox.get_domains(api, "pve1.test")
        proxmox.get_domains(api, "pve2.test")
        immediately_after = [record.getMessage() for record in caplog.records]
        caplog.clear()

        clock.now += proxmox._WARNING_INTERVAL + 1
        proxmox.get_domains(api, "pve1.test")
        proxmox.get_domains(api, "pve2.test")
        an_hour_later = [record.getMessage() for record in caplog.records]

    assert len(both) == 2, (
        f"two hosts with an empty node index drew {both}. One host's warning silenced the "
        "other's, so the second host's misconfiguration is invisible")
    for name in ("pve1.test", "pve2.test"):
        assert sum(name in message for message in both) == 1, (
            f"{name} is not named exactly once in {both}")
    assert immediately_after == [], (
        f"the warnings repeated on the very next refresh: {immediately_after}")
    assert len(an_hour_later) == 2, (
        f"the interval passed and only {an_hour_later} came back; each host has to be "
        "reported again on its own timer")


def test_the_two_throttled_warnings_do_not_share_one_timer(caplog):
    """Same host, same hour, two different faults — and the second must still be reported.

    They are throttled through one dict, so the key has to carry WHICH warning it is as
    well as which host. A host that was pointed at the wrong address and is then pointed at
    a real PVE whose token has no ACL has swapped one standing misconfiguration for
    another; a shared timer would swallow the second one and leave the operator staring at
    a diagnosis they have already fixed.

    No clock is moved: microseconds pass between the two calls, so only distinct keys can
    produce the second line.
    """
    with caplog.at_level("WARNING"):
        proxmox.get_domains(_Proxmox(nodes=[]), "pve1.test")
        proxmox.get_domains(_Proxmox(nodes=ONE_NODE, vms=[]), "pve1.test")
        warned = [record.getMessage() for record in caplog.records]

    assert len(warned) == 2, f"expected both warnings, got {warned}"
    assert "NO nodes" in warned[0], f"the node-index warning is missing: {warned}"
    assert "NOT ONE guest" in warned[1], (
        f"the no-guests warning was swallowed by the node-index one's timer: {warned}")


def test_nodes_listed_with_not_one_guest_behind_them_points_at_the_missing_token_acl(caplog):
    """The failure mode with no error anywhere: a token whose own ACL was never granted.

    Nothing about this looks broken from outside. The token authenticates, the node
    listing answers in full, every call returns 200 — and `nodes/<node>/qemu` hands back
    an empty list, so the host contributes no names and the zone quietly shrinks. Nodes
    present and zero guests between them is the only shape this leaves behind, so it is
    the only thing the service can watch for, and the warning has to carry the fix.

    It also has to name LXC. A host running only containers reaches this exact shape
    legitimately — the service reads QEMU guests only — and without the caveat the line
    reads as a permission fault on a host that has none.
    """
    api = _Proxmox(nodes=ONE_NODE, vms=[])

    with caplog.at_level("WARNING"):
        domains = proxmox.get_domains(api, "pve1.test")

    warned = [record.getMessage() for record in caplog.records]
    assert domains == [], f"an empty answer is still an answer and must be published: {domains!r}"
    assert len(warned) == 1, f"expected one warning, got {warned}"
    assert "pve1.test" in warned[0], f"the warning does not say which host went empty:\n{warned[0]}"
    assert "pveum acl modify /vms" in warned[0], (
        "the warning does not carry the command that fixes it, which is the whole "
        f"actionable part — the cause is invisible from every other angle:\n{warned[0]}")
    assert "LXC" in warned[0], (
        "the warning does not mention LXC. A host running only containers produces this "
        f"same shape and has nothing to fix, so the line must say so:\n{warned[0]}")


def test_the_warning_repeats_hourly_rather_than_once_or_every_refresh(monkeypatch, caplog):
    """The throttle is an interval, and both halves of that are load-bearing.

    Quiet in between, because get_domains runs on every full refresh — and a full refresh
    is not the once-a-minute event `full_refresh_interval` makes it look like:
    update_dns_periodically() in src/app.py also refreshes the moment the inventory it
    samples every 2 s has CHANGED, so the minute is a lower bound and a couple of seconds
    is the floor. A host with no QEMU guests is a legitimate configuration, so an
    unthrottled line drowns the log it is supposed to stand out in. But it DOES come back:
    the fault holds for as long as the host is misconfigured, and a line that scrolled past
    during the incident is no use to whoever looks later. A timestamp is also what keeps
    the throttle from latching — the worst a stale entry can cost is one interval, not
    every future warning.
    """
    clock = _Clock()
    monkeypatch.setattr(proxmox, "time", clock)
    api = _Proxmox(nodes=ONE_NODE, vms=[])

    with caplog.at_level("WARNING"):
        proxmox.get_domains(api, "pve1.test")
        first = [record.getMessage() for record in caplog.records]
        caplog.clear()

        proxmox.get_domains(api, "pve1.test")
        immediately_after = [record.getMessage() for record in caplog.records]
        caplog.clear()

        clock.now += proxmox._WARNING_INTERVAL + 1
        proxmox.get_domains(api, "pve1.test")
        an_hour_later = [record.getMessage() for record in caplog.records]

    assert len(first) == 1, f"expected one warning, got {first}"
    assert immediately_after == [], (
        f"the warning repeated on the very next refresh: {immediately_after}\nA refresh can "
        "come every couple of seconds, forever, on a setup that may well be fine")
    assert len(an_hour_later) == 1, (
        f"the interval passed and the warning did not come back: {an_hour_later}\nA one-shot "
        "leaves whoever reads the log after the incident with nothing to find")
    # The clock above is advanced BY the constant, so the test proves an interval and not
    # its length — every assertion above holds just as well at one second or at a week.
    # README.md tells the operator that BOTH throttled lines come "at most once an hour per
    # host" — this no-guests one and the empty-node-index one, which rides on the very same
    # constant — and this is the only thing tying that promise to the code. Renaming the
    # constant to something guests-specific again would be the first step to giving them
    # separate timers by accident.
    assert proxmox._WARNING_INTERVAL == 3600, (
        f"the interval is {proxmox._WARNING_INTERVAL} s, and README.md promises an hour for "
        "the no-guests line AND for the empty-node-index line — change them together or "
        "not at all")


def test_the_throttle_is_kept_per_host_and_not_shared_between_them(monkeypatch, caplog):
    """Each host is its own fault, so each host gets its own line and its own silence.

    The service polls several INDEPENDENT PVE endpoints, each on its own thread and each
    with its own token, so two of them going empty is two separate things to fix. A
    throttle keyed on anything less than the host would let whichever host warned first
    silence every other host for an hour.

    tests/conftest.py configures two hosts for exactly this kind of regression, which no
    single-host test can catch: with one host name in play, a constant key behaves
    identically to a per-host one.
    """
    clock = _Clock()
    monkeypatch.setattr(proxmox, "time", clock)
    api = _Proxmox(nodes=ONE_NODE, vms=[])

    with caplog.at_level("WARNING"):
        proxmox.get_domains(api, "pve1.test")
        proxmox.get_domains(api, "pve2.test")
        both = [record.getMessage() for record in caplog.records]
        caplog.clear()

        proxmox.get_domains(api, "pve1.test")
        proxmox.get_domains(api, "pve2.test")
        immediately_after = [record.getMessage() for record in caplog.records]
        caplog.clear()

        clock.now += proxmox._WARNING_INTERVAL + 1
        proxmox.get_domains(api, "pve1.test")
        proxmox.get_domains(api, "pve2.test")
        an_hour_later = [record.getMessage() for record in caplog.records]

    assert len(both) == 2, (
        f"two empty hosts drew {both}. One host's warning silenced the other's, so the "
        "second host's outage is invisible for the rest of the interval")
    for name in ("pve1.test", "pve2.test"):
        assert sum(name in message for message in both) == 1, (
            f"{name} is not named exactly once in {both}; a line that does not say which "
            "host went empty sends whoever reads it to the wrong machine")
    assert immediately_after == [], (
        f"the warnings repeated on the very next refresh: {immediately_after}")
    assert len(an_hour_later) == 2, (
        f"the interval passed and only {an_hour_later} came back; each host has to be "
        "reported again on its own timer")


def test_a_host_whose_guests_are_all_templates_is_not_blamed_on_the_token(caplog):
    """Zero NAMES is not zero guests, and only the second one says anything about the ACL.

    The listing answered with a guest; it just happens to be a template, which the walk
    skips because a template has no address to publish. That is an ordinary host doing an
    ordinary thing, and pointing `pveum acl modify` at it sends whoever reads the log to
    fix permissions that were never broken. So the count has to be taken from what the
    listing RETURNED, before the template filter — not from the slice that comes out of it.
    """
    with caplog.at_level("WARNING"):
        domains = proxmox.get_domains(_Proxmox(nodes=ONE_NODE, vms=[TEMPLATE_VM]), "pve1.test")

    warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert domains == [], "a template has no address to publish and must not enter the zone"
    assert warnings == [], (
        f"a host holding nothing but templates drew {warnings}. The listing answered and the "
        "token can plainly see the guest — the empty slice is the template filter's doing")


def test_a_failed_node_does_not_silence_the_warning_for_the_nodes_that_answered(caplog):
    """The mixed cluster: one node down, and the nodes that DID answer showed no guests.

    The warning fires, and suppressing it here was the bug. A host-level "some node
    failed" flag meant a cluster with one permanently offline node could never draw this
    diagnosis again, however broken its token was — and that silence is precisely what
    would hide the broken token for as long as the node stayed down. What the failed node
    did not answer says nothing about what the other nodes did answer, and those answers
    are the whole signature.

    What the failed node earns instead is a CLAUSE NAMING IT: its guests are unknown, so
    the missing names may simply live there, and whoever reads the line has to know that
    before going after permissions. The per-node ERROR is unchanged and still logged on
    its own — the warning adds to it rather than replacing it.
    """
    cluster = _Cluster({
        "node-down": _Node(_BrokenQemu(RuntimeError("500 internal server error"))),
        "node-up": _Node(_Qemu([], AGENT_ANSWER)),
    })

    # WARNING, not ERROR: at_level sets a floor, and asking for ERROR would drop the
    # very warning this test exists to catch while still passing.
    with caplog.at_level("WARNING"):
        domains = proxmox.get_domains(cluster, "pve1.test")

    assert domains == []
    errors = [r.getMessage() for r in caplog.records if r.levelname == "ERROR"]
    assert any("node-down" in message for message in errors), (
        f"the node that failed did not log an ERROR naming itself: {errors}")
    warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 1, (
        f"expected the no-guests warning alongside the per-node ERROR, got {warnings}. "
        "The node that answered showed no guests, which is the signature, and one node "
        "being down is no reason to stop diagnosing the host")
    assert "pveum acl modify /vms" in warnings[0], (
        f"the warning lost the command that fixes the likely cause:\n{warnings[0]}")
    assert "node-down" in warnings[0], (
        "the warning does not name the node that never answered, so it reads as a flat "
        "permission diagnosis on a host whose missing guests may simply live on the node "
        f"that is down:\n{warnings[0]}")


def test_recovery_does_not_re_arm_either_warning_inside_the_interval(caplog):
    """The throttle is unconditional — recovery does not clear it, and that is the point.

    Both warnings used to be re-armed on recovery, and that defeated the throttle rather
    than refining it: the condition that fires each line and the condition that would clear
    it are exact complements, so ANY alternation emitted a line on every transition. On a
    two-node cluster where the QEMU-holding node flaps beside an LXC-only one, that was ten
    warnings in forty seconds — from a mechanism whose entire job is to hold the line to one
    an hour.

    What the removal costs is bounded and was already accepted for stale entries: a fault
    that clears and comes back inside the interval waits out the rest of it, up to an hour
    of silence on a genuinely new breakage. The recovery step below is asserted to be real,
    so this cannot pass on a walk that never produced guests in the first place.

    No clock is moved here on purpose: microseconds pass, so anything that produces a second
    line is a reset that should no longer exist.
    """
    empty = _Proxmox(nodes=ONE_NODE, vms=[])
    populated = _Proxmox(nodes=ONE_NODE, vms=[RUNNING_VM], agent_result=AGENT_ANSWER)
    no_nodes = _Proxmox(nodes=[])

    with caplog.at_level("WARNING"):
        proxmox.get_domains(empty, "pve1.test")
        recovered = proxmox.get_domains(populated, "pve1.test")
        caplog.clear()
        proxmox.get_domains(empty, "pve1.test")
        guests_broke_again = [record.getMessage() for record in caplog.records]
        caplog.clear()

        proxmox.get_domains(no_nodes, "pve2.test")
        proxmox.get_domains(populated, "pve2.test")
        caplog.clear()
        proxmox.get_domains(no_nodes, "pve2.test")
        nodes_broke_again = [record.getMessage() for record in caplog.records]

    assert [entry["domain"] for entry in recovered] == ["foo.lc"], (
        "the recovery step did not actually produce guests, so this test would pass on a "
        "throttle that resets on every call")
    assert guests_broke_again == [], (
        f"the no-guests warning came back inside the interval: {guests_broke_again}\nSomething "
        "clears the throttle on recovery, and a host that alternates then warns on every "
        "single transition — which is the throttle not applying at all")
    assert nodes_broke_again == [], (
        f"the node-index warning came back inside the interval: {nodes_broke_again}\nSame "
        "reset, other key: nodes coming back must not re-arm the empty-index line")


def test_a_host_with_no_failed_nodes_says_nothing_about_nodes_that_did_not_answer(caplog):
    """The failed-node clause is CONDITIONAL, and an unguarded one reads as a real claim.

    Every node answered; there is nothing unaccounted for. Rendering the clause anyway —
    which is what dropping the guard does, since joining an empty list of names is silent
    about being empty — produces a line that tells the operator some node did not answer
    and names none, sending them to look for an outage that is not there.
    """
    with caplog.at_level("WARNING"):
        proxmox.get_domains(_Proxmox(nodes=ONE_NODE, vms=[]), "pve1.test")

    warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 1, f"expected the no-guests warning, got {warnings}"
    assert "did not answer" not in warnings[0], (
        "no node failed, and the warning still carries the clause about a node that did "
        f"not answer:\n{warnings[0]}")
    assert "see the ERROR above" not in warnings[0], (
        "the warning points at an ERROR that was never logged, because no node failed:"
        f"\n{warnings[0]}")


def test_the_failed_node_clause_is_singular_for_a_single_node(caplog):
    """One node down is the common case, and "whether they hold guests" is wrong for it."""
    cluster = _Cluster({
        "node-down": _Node(_BrokenQemu(RuntimeError("500 internal server error"))),
        "node-up": _Node(_Qemu([], AGENT_ANSWER)),
    })

    with caplog.at_level("WARNING"):
        proxmox.get_domains(cluster, "pve1.test")

    warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 1, f"expected the no-guests warning, got {warnings}"
    assert "whether it holds guests is unknown" in warnings[0], (
        f"one node failed and the clause is written in the plural:\n{warnings[0]}")


def test_a_node_that_answers_with_no_listing_at_all_does_not_count_as_having_answered(caplog):
    """"Answered" has to mean "handed back an enumerable listing", or the diagnosis lies.

    proxmoxer returns the endpoint's `data` as-is, so `{"data": null}` reaches the walk as
    None and raises TypeError the moment it is counted. The node belongs in the failed
    list and nowhere else. Counting it as answered first puts it in BOTH tallies, and on a
    single-node host that is exactly the shape the ACL diagnosis fires on — a confident
    "your token has no ACL" for a node that never produced a listing to filter.
    """
    cluster = _Cluster({"pve": _Node(_UnenumerableQemu())})

    with caplog.at_level("WARNING"):
        domains = proxmox.get_domains(cluster, "pve1.test")

    assert domains == []
    errors = [r.getMessage() for r in caplog.records if r.levelname == "ERROR"]
    assert any("pve" in message for message in errors), (
        f"the node whose listing could not be read did not log an ERROR naming itself: {errors}")
    warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert warnings == [], (
        f"a node that handed back nothing enumerable drew {warnings}. It answered with no "
        "listing at all, so there is no empty permission filter to diagnose — the ERROR "
        "already says what went wrong")


def test_every_node_failing_is_left_to_the_per_node_errors(caplog):
    """Zero guests because nothing answered is a different fault with a different cause.

    Every node's guest listing raised, each one already logged its own ERROR, and none of
    it has anything to do with the token's ACL. Stacking the ACL warning on top would
    point whoever reads the log at a permission problem that is not there.
    """
    cluster = _Cluster({
        "pve1": _Node(_BrokenQemu(RuntimeError("500 internal server error"))),
        "pve2": _Node(_BrokenQemu(RuntimeError("596 connection timed out"))),
    })

    with caplog.at_level("WARNING"):
        domains = proxmox.get_domains(cluster, "pve1.test")

    assert domains == []
    warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert warnings == [], (
        f"a host whose every node failed drew {warnings}. Those nodes never answered, so "
        "nothing here says the token's permissions are empty — the per-node ERRORs already "
        "say what went wrong")


def test_a_populated_host_stamps_its_name_on_every_entry():
    domains = proxmox.get_domains(
        _Proxmox(nodes=ONE_NODE, vms=[RUNNING_VM], agent_result=AGENT_ANSWER), "pve1.test")

    assert domains == [{"domain": "foo.lc", "ipv4": "10.0.0.5", "ipv6": "::",
                        "host": "pve1.test", "vmid": 100, "status": "running"}]


def test_every_node_of_a_cluster_contributes_its_guests():
    """The ordinary multi-node case, and the control for the test below it.

    Without it, a loop that stopped after the first node — or one that abandoned the
    whole fetch the moment any node misbehaved — would still satisfy the partial-read
    test below, which only asks that the healthy node's guests come through.
    """
    cluster = _Cluster({
        "pve1": _Node(_Qemu([RUNNING_VM], AGENT_ANSWER)),
        "pve2": _Node(_Qemu([OTHER_VM], AGENT_ANSWER)),
    })

    domains = proxmox.get_domains(cluster, "pve1.test")

    assert [entry["domain"] for entry in domains] == ["foo.lc", "bar.lc"]


def test_one_node_failing_costs_only_that_node_and_is_logged(caplog):
    """One node of a cluster failing does NOT abandon the other nodes' guests.

    This pins behaviour that predates multi-host support and that this change left
    alone on purpose. The healthy node's guests come through; the failed node's are
    simply absent, and the caller — which cannot tell this list from a complete one —
    publishes it, so those names leave the zone until the node answers again. The
    per-node ERROR asserted here is the only thing that says so, which is why it has
    to name the node.

    A fix belongs in its own change, on its own evidence: neither candidate is free.
    Carrying the failed node's previous entries over serves records nothing has
    confirmed, with no rule for when to drop them; returning None instead freezes the
    host's healthy nodes for the whole outage AND, since the caller only advances its
    refresh bookkeeping after a successful fetch, turns the once-a-minute full walk
    into one every couple of seconds — a guest-agent call per VM each time.
    """
    cluster = _Cluster({
        "pve1": _Node(_Qemu([RUNNING_VM], AGENT_ANSWER)),
        "pve2": _Node(_BrokenQemu(RuntimeError("500 internal server error"))),
    })

    with caplog.at_level("ERROR"):
        domains = proxmox.get_domains(cluster, "pve1.test")

    assert [entry["domain"] for entry in domains] == ["foo.lc"], (
        f"a node failed and the fetch came back with {domains!r}. The healthy node's "
        "guests are the part that IS known, and dropping them — or handing back None — "
        "takes the whole host's names out of the zone over one broken node")
    assert "pve2" in caplog.text, (
        f"the failure does not name the node it happened on:\n{caplog.text}")


def test_a_stopped_guest_carries_the_fields_the_merge_ranks_on():
    """The early return, and the one that matters most: without `status` this entry
    would be indistinguishable from a running guest whose agent said nothing."""
    entry = proxmox.get_vm_ip(_Proxmox(nodes=ONE_NODE), {"node": "pve"}, STOPPED_VM, "pve2.test")

    assert entry == {"domain": "baz.lc", "ipv4": "0.0.0.0", "ipv6": "::",
                     "host": "pve2.test", "vmid": 101, "status": "stopped"}


def test_a_guest_agent_that_fails_still_produces_a_rankable_entry():
    """The except branches. A running guest whose agent is missing still outranks a
    stopped one, so these paths cannot be the ones that drop `status`."""
    proxmox_api = _Proxmox(nodes=ONE_NODE, agent_result=RuntimeError("no QEMU guest agent"))
    entry = proxmox.get_vm_ip(proxmox_api, {"node": "pve"}, RUNNING_VM, "pve2.test")

    assert entry == {"domain": "foo.lc", "ipv4": "0.0.0.0", "ipv6": "::",
                     "host": "pve2.test", "vmid": 100, "status": "running"}
