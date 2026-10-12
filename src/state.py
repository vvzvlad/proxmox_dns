"""Shared runtime registry of resolved VM domains.

The DNS and HTTP servers read this name; writers rebind it to a freshly merged
list rather than mutating it in place. Access it as ``state.servers_list``
(attribute lookup), never import the list object, or the reader stops seeing updates.

Writers, all in src/app.py: the harvest in ``initial_domains()`` (once at startup),
and ``_publish_locked()``, reached by each host's updater via ``publish_domains()``
and by a startup fetch that answered after the harvest closed (only while
``HostState.has_published`` is false, so it never overwrites a fresher slice).

``_publish_lock`` serialises them: a publisher stores its own slice and then reads
every host's slice to rebuild this list, so unserialised publishers could rebind an
older merged view last. The rebind being atomic does not make the lock redundant.
"""

servers_list: list[dict] = []
