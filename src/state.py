"""Shared runtime registry of resolved VM domains.

The DNS and HTTP servers read from this name; everything else REBINDS it to a
freshly merged list rather than mutating the list in place. Access it as
``state.servers_list`` (attribute lookup on this module) rather than importing the
list object directly, so every reader observes the reassignment — importing the
object would pin whichever list happened to be here at import time, and the zone
would stop updating for that reader without anything failing.

THREE KINDS OF WRITER IN src/app.py, AT TWO ASSIGNMENT SITES — and ``run()`` is
neither: it assigns this name nowhere. The first site is the harvest in
``initial_domains()``, which writes this name once at startup, with the pre-fill it
collected, before any updater thread exists. The second is ``_publish_locked()``, and
two kinds of caller reach it: each host's updater thread, via ``publish_domains()``,
which is the steady-state writer; and a startup fetch that answered LATE — after
``initial_domains()`` had closed its harvest — which publishes its own host's slice
from its own thread rather than throwing the answer away. That late writer is the one
that made this lock carry more weight than "several updaters at once", and
``HostState.has_published`` is what stops it: a late fetch publishes only while nothing
has filled its host's slice yet, so it can never land on top of a fresher slice that
host's own updater published in the meantime.

The publishers are serialised by ``_publish_lock`` in src/app.py, and that lock is
load-bearing rather than defensive: a publisher first stores its OWN host's slice
and then reads EVERY host's slice to rebuild this list, so two threads publishing
at once could each build a merged list from a different set of slices and the
later rebind would win with the older view. Do not "simplify" it away on the
grounds that the rebind itself is atomic — the rebind is not what races.
"""

servers_list: list[dict] = []
