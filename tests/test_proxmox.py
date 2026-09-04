"""What src/proxmox.py has to hand back for the merge to work, and the silent failures.

Three things are pinned here.

EVERY entry carries where it came from. `host`, `vmid` and `status` are what
src/app.py's merge ranks a collision on, and get_vm_ip() returns from four places —
the stopped guest, the successful read, and two except branches. An entry that lost
`status` on one of those paths cannot be ranked as running and would quietly lose a
collision it should have won, which is the sort of bug that shows up as one VM being
unreachable by name and nothing in the log at all.

AND an empty node list is reported. An API token defaults to privilege separation, so
a token without an ACL of its own authenticates perfectly and gets an empty list back
from every listing endpoint — no error, no exception, nothing to notice. The zone just
loses that host's names. The warning is the only thing standing between that and a
silent outage.

AND A PARTIAL ANSWER IS STILL AN ANSWER, which is the behaviour rather than the ideal.
On a multi-node cluster one node's guest list can fail while the others succeed, and
what comes back is a list short by that node's guests, indistinguishable from a complete
one. The test below pins that as it stands — it predates multi-host support and this
change deliberately left it alone — so that whoever changes it does so knowingly and not
by accident. Only the NODE LISTING failing gives back None, the caller's "keep the slice
you have" signal.
"""

from src import proxmox


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
AGENT_ANSWER = {"result": [{"name": "eth0", "ip-addresses": [
    {"ip-address-type": "ipv4", "ip-address": "10.0.0.5"}]}]}


def test_an_empty_node_list_is_reported_rather_than_served_silently(caplog):
    """The failure mode with no error anywhere: a token whose ACL was never granted.

    The empty result is still returned — a host that genuinely has no VMs is a
    legitimate configuration, and keeping its old records forever would mean answering
    with addresses of guests that no longer exist. So the log line is the whole of the
    signal, and it has to name the host and point at the cause.
    """
    with caplog.at_level("WARNING"):
        domains = proxmox.get_domains(_Proxmox(nodes=[]), "pve1.test")

    assert domains == [], "an empty host must publish an empty slice, not None"
    assert len(caplog.records) == 1, (
        f"expected one warning, got {[r.getMessage() for r in caplog.records]}")
    assert "pve1.test" in caplog.text, "the warning does not say which host answered empty"
    assert "token" in caplog.text, (
        "the warning does not point at the API token's missing ACL, which is the "
        f"overwhelmingly likely cause and the only actionable part:\n{caplog.text}")


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
