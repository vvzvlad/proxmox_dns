"""Turn a pydantic-settings startup failure into a clear, actionable message.

Reused by every entrypoint that builds settings so a missing or invalid
environment variable fails fast with a readable message (naming the env var)
instead of a raw pydantic traceback.

TWO exception types, not one, and they are unrelated classes that happen to share
ValueError. A value that violates the model is a ValidationError. A value that
pydantic-settings cannot even turn INTO a value is a SettingsError, raised by the
source before validation ever runs. Three plain string variables could not fail
that way; one variable holding a JSON list can, and does, the moment an operator
wraps it across two lines or clears it and leaves `PROXMOX_HOSTS=` behind.

SettingsError is itself two cases sharing one class, and they are told apart by
`__cause__` rather than by the class: a value the JSON decoder rejected (the
common one here) and a value the source could not even read. Both are reported,
each in its own words.
"""

import json
import re
import sys
from typing import Callable, TypeVar

from pydantic import ValidationError
from pydantic_settings import SettingsError

T = TypeVar("T")

# pydantic-settings reports an unparseable complex field as
# SettingsError('error parsing value for field "proxmox_hosts" from source "..."').
# The field name is the only actionable part of it and the exception carries no
# attribute for it, so it is read back out of the message. A miss is not fatal —
# the message below falls back to naming no variable rather than to a traceback.
_SETTINGS_ERROR_FIELD = re.compile(r'field "([^"]+)"')


def _render_location(loc) -> str:
    """Render a pydantic error location as the env var plus the path inside it.

    loc[0] is the field name and the env var is its upper-case form, but for a
    complex field the error is usually somewhere INSIDE the parsed value:
    ("proxmox_hosts", 1, "token_value") is a bad token on the second host.
    Printing loc[0] alone would tell an operator with four PVE hosts configured
    that the whole variable is wrong and leave them to find out which entry.

    Integer segments become `[i]` and string ones `.name`, so that example reads
    PROXMOX_HOSTS[1].token_value. A single-segment loc renders exactly as it
    always did.
    """
    if not loc:
        return "?"
    rendered = str(loc[0]).upper()
    for segment in loc[1:]:
        rendered += f"[{segment}]" if isinstance(segment, int) else f".{segment}"
    return rendered


def load_settings_or_exit(factory: Callable[[], T]) -> T:
    """Build a settings object via `factory` (e.g. a BaseSettings subclass).

    On a configuration ValidationError or SettingsError, print a clear message
    that names the offending environment variable(s) and exit(1) — no pydantic
    traceback. Anything else is left to propagate unchanged.
    """
    try:
        return factory()
    except SettingsError as exc:
        # The value never reached the model: pydantic-settings raised from the source
        # instead of validating. Rendered in the same shape as the block below, because
        # from the operator's side it is the same event — a variable in .env is wrong
        # and the message has to say which one and why.
        match = _SETTINGS_ERROR_FIELD.search(str(exc))
        name = match.group(1).upper() if match else "?"
        cause = exc.__cause__
        # WHICH KIND of SettingsError this is has to come off the CAUSE, not off the
        # exception type. pydantic-settings raises the same class from two places: it
        # wraps a failed decode ("error parsing value for field ...", caused by a
        # JSONDecodeError) and a failed read ("error getting value for field ...",
        # caused by whatever the source threw). Calling both "not valid JSON" tells an
        # operator with the second one to go and fix JSON that is perfectly fine — and
        # for a SettingsError whose message carries no `field "..."` at all it produced
        # `- ?: the value is not valid JSON`, which says nothing whatsoever.
        if isinstance(cause, json.JSONDecodeError):
            # The decoder carries the column it gave up at — the difference between
            # "your JSON is wrong" and "your JSON stops after 200 characters", which is
            # what a value wrapped onto a second line looks like from here.
            problem = f"the value is not valid JSON ({cause})"
            advice = [
                "It has to be ONE line of JSON: .env has no line continuation, so a value "
                "wrapped across two lines is cut at the first newline. An empty value is "
                "not valid JSON either — remove the variable rather than blanking it.",
            ]
        else:
            # Whatever actually went wrong, in its own words. The wrapper's text names
            # only the field and the source, both of which are already on the line above.
            problem = str(cause) if cause is not None else str(exc)
            advice = []
        lines = [
            "Configuration error in environment / .env:",
            "  Invalid value(s):",
            f"    - {name}: {problem}",
            "",
            *advice,
            "Set it in .env (see .env.example) and try again.",
        ]
        print("\n".join(lines), file=sys.stderr)
        raise SystemExit(1)
    except ValidationError as exc:
        missing: list[str] = []
        invalid: list[str] = []
        for err in exc.errors():
            name = _render_location(err.get("loc"))
            if err.get("type") == "missing":
                missing.append(name)
            else:
                invalid.append(f"{name}: {err.get('msg')}")
        lines = ["Configuration error in environment / .env:"]
        if missing:
            lines.append("  Missing required variable(s):")
            lines.extend(f"    - {n}" for n in missing)
        if invalid:
            lines.append("  Invalid value(s):")
            lines.extend(f"    - {item}" for item in invalid)
        lines.append("")
        lines.append("Set them in .env (see .env.example) and try again.")
        print("\n".join(lines), file=sys.stderr)
        raise SystemExit(1)
