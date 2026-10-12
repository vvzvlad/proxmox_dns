"""What src/proxmox.py has to hand back for the merge to work, and the silent failures.

Every entry carries `host`, `vmid` and `status`, which src/app.py's merge ranks a
collision on, on all four return paths of get_vm_ip() (stopped guest, successful read,
two except branches). An entry missing `status` would silently lose a collision.

A partial answer is still an answer: when one node's guest list fails on a multi-node
cluster, the result is short by that node's guests and indistinguishable from a complete
one. Pinned as current behaviour so a change to it is deliberate. Only the node listing
failing returns None, the caller's "keep the slice you have" signal.
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
TEMPLATE_VM = {"vmid": 900, "name": "tmpl-deb12", "status": "stopped", "template": 1}
AGENT_ANSWER = {"result": [{"name": "eth0", "ip-addresses": [
    {"ip-address-type": "ipv4", "ip-address": "10.0.0.5"}]}]}


def test_a_populated_host_stamps_its_name_on_every_entry():
    domains = proxmox.get_domains(
        _Proxmox(nodes=ONE_NODE, vms=[RUNNING_VM], agent_result=AGENT_ANSWER), "pve1.test")

    assert domains == [{"domain": "foo.lc", "ipv4": "10.0.0.5", "ipv6": "::",
                        "host": "pve1.test", "vmid": 100, "status": "running"}]


def test_nodes_with_no_guests_behind_them_are_an_empty_slice_not_none():
    """The startup ERROR in src/app.py keys on exactly this `[]`; None would keep a stale slice."""
    domains = proxmox.get_domains(_Proxmox(ONE_NODE), "pve1.test")

    assert domains == [], f"nodes listed, no guests: expected [], got {domains!r}"


def test_a_template_never_enters_the_zone():
    domains = proxmox.get_domains(_Proxmox(nodes=ONE_NODE, vms=[TEMPLATE_VM]), "pve1.test")

    assert domains == [], "a template has no address to publish and must not enter the zone"


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

    The healthy node's guests come through; the failed node's are absent, and the caller
    publishes the list, so those names leave the zone until the node answers. The
    per-node ERROR is the only signal, so it must name the node.

    Neither alternative is free: carrying the failed node's previous entries serves
    unconfirmed records, and returning None freezes the healthy nodes and, since the
    caller advances its refresh bookkeeping only after a successful fetch, turns the
    once-a-minute full walk into one every couple of seconds.
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
