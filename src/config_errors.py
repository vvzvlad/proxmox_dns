"""Turn a pydantic-settings startup failure into a clear, actionable message.

Reused by every entrypoint that builds settings so a missing or invalid
environment variable fails fast with a readable message (naming the env var)
instead of a raw pydantic traceback.

Two unrelated exception types: a value that violates the model is a
ValidationError; a value pydantic-settings cannot parse at all (e.g. PROXMOX_HOSTS
JSON wrapped across two lines, or left empty) is a SettingsError raised by the
source before validation. SettingsError covers a JSON decode failure and a read
failure, told apart by `__cause__`.
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
# The exception carries no attribute for the field name, so it is read from the
# message; on a miss the report names `?` instead.
_SETTINGS_ERROR_FIELD = re.compile(r'field "([^"]+)"')


def _render_location(loc) -> str:
    """Render a pydantic error location as the env var plus the path inside it.

    loc[0] is the field name (the env var is its upper-case form); further segments
    point inside the parsed value. Integers become `[i]` and strings `.name`, so
    ("proxmox_hosts", 1, "token_value") reads PROXMOX_HOSTS[1].token_value.
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
        # The value never reached the model. Rendered in the same shape as the
        # ValidationError block below.
        match = _SETTINGS_ERROR_FIELD.search(str(exc))
        name = match.group(1).upper() if match else "?"
        cause = exc.__cause__
        # The kind comes from the cause: pydantic-settings raises the same class for a
        # failed decode (caused by JSONDecodeError) and a failed read (caused by
        # whatever the source threw).
        if isinstance(cause, json.JSONDecodeError):
            # The decoder's message includes the column, which shows a value cut at a
            # line break.
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
