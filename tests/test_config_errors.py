import json

import pytest
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict, SettingsError

from src.config_errors import load_settings_or_exit
from src.settings import Settings


# Throwaway settings models. They explicitly do NOT read the project .env
# (env_file=None) so each test is hermetic.
class _Req(BaseSettings):
    some_required_value: str
    model_config = SettingsConfigDict(env_file=None, extra="ignore")


class _Ranged(BaseSettings):
    level: int = Field(ge=0, le=3)
    model_config = SettingsConfigDict(env_file=None, extra="ignore")


class _Entry(BaseModel):
    name: str
    secret: str


class _Nested(BaseSettings):
    """The shape src/settings.py now has: one env var holding a list of models."""

    entries: list[_Entry]
    model_config = SettingsConfigDict(env_file=None, extra="ignore")


def test_missing_required_exits_with_clear_message(capsys, monkeypatch):
    monkeypatch.delenv("SOME_REQUIRED_VALUE", raising=False)
    with pytest.raises(SystemExit) as ei:
        load_settings_or_exit(_Req)
    assert ei.value.code == 1
    err = capsys.readouterr().err
    assert "SOME_REQUIRED_VALUE" in err
    assert "Missing required" in err


def test_invalid_value_exits_with_clear_message(capsys, monkeypatch):
    monkeypatch.setenv("LEVEL", "9")
    with pytest.raises(SystemExit) as ei:
        load_settings_or_exit(_Ranged)
    assert ei.value.code == 1
    err = capsys.readouterr().err
    assert "LEVEL" in err
    assert "Invalid" in err


def test_error_inside_a_list_entry_names_the_index_and_the_field(capsys, monkeypatch):
    """An operator with four PVE hosts configured must be told WHICH one is wrong.

    pydantic reports this as loc ("entries", 1, "secret"). Printing loc[0] alone —
    which is what this module used to do — says only that ENTRIES is bad, and the
    variable it names is a JSON list that may hold half a dozen hosts. The whole
    path is the difference between one fix and a search.
    """
    monkeypatch.setenv("ENTRIES", json.dumps([{"name": "a", "secret": "s"}, {"name": "b"}]))
    with pytest.raises(SystemExit) as ei:
        load_settings_or_exit(_Nested)
    assert ei.value.code == 1
    err = capsys.readouterr().err
    assert "ENTRIES[1].secret" in err, (
        f"the message does not say which entry or which field is missing:\n{err}")


def test_json_that_does_not_parse_names_the_variable_instead_of_raising(capsys, monkeypatch):
    """The failure mode the JSON config format introduced, against the REAL settings.

    pydantic-settings cannot turn this value into anything, so it raises SettingsError
    from the source — BEFORE validation, and NOT a ValidationError; the two share only
    ValueError. A guard that catches only ValidationError therefore lets it past, and
    what the operator gets is the raw traceback this module exists to prevent. Three
    plain string variables could not fail this way; one variable holding a JSON list
    can, and a mistyped or wrapped value is how.
    """
    monkeypatch.setenv("PROXMOX_HOSTS", "not-json")

    with pytest.raises(SystemExit) as ei:
        load_settings_or_exit(lambda: Settings(_env_file=None))

    assert ei.value.code == 1
    err = capsys.readouterr().err
    assert "PROXMOX_HOSTS" in err, (
        f"the message does not name the variable that is wrong:\n{err}")
    assert "JSON" in err, (
        f"the message does not say what is wrong with the value:\n{err}")
    assert "Traceback" not in err, f"a traceback reached the operator:\n{err}"


def test_a_variable_left_empty_is_reported_rather_than_traced_back(capsys, monkeypatch):
    """`PROXMOX_HOSTS=` is what an operator leaves behind after clearing the value.

    An empty string is not valid JSON either, so it takes the same path as a mistyped
    one — and it is the likelier of the two to be reached by accident.
    """
    monkeypatch.setenv("PROXMOX_HOSTS", "")

    with pytest.raises(SystemExit) as ei:
        load_settings_or_exit(lambda: Settings(_env_file=None))

    assert ei.value.code == 1
    err = capsys.readouterr().err
    assert "PROXMOX_HOSTS" in err, (
        f"the message does not name the variable that is empty:\n{err}")
    assert "Traceback" not in err, f"a traceback reached the operator:\n{err}"


def test_a_settings_error_that_is_not_about_json_says_what_actually_went_wrong(capsys):
    """SettingsError is TWO failures wearing one class, and only one of them is JSON.

    pydantic-settings raises it both for a value its JSON decoder rejected ("error
    parsing value for field ...") and for a value the source could not read at all
    ("error getting value for field ...", from a different `raise` with a different
    cause). A message hardcoded to "the value is not valid JSON" sends an operator
    holding the second one off to fix JSON that parses perfectly — and for a
    SettingsError whose text carries no `field "..."` the whole line degrades to
    `- ?: the value is not valid JSON`, which names nothing and explains nothing.

    Raised directly rather than provoked through pydantic-settings: this branch is
    about what the module does with an exception it is handed, and reproducing the
    library's internal read failure would pin this test to its internals instead.
    """
    cause = OSError("secrets_dir is not readable")

    def source_that_cannot_read_its_value():
        raise SettingsError(
            'error getting value for field "proxmox_hosts" from source "SecretsSettingsSource"'
        ) from cause

    with pytest.raises(SystemExit) as ei:
        load_settings_or_exit(source_that_cannot_read_its_value)

    assert ei.value.code == 1
    err = capsys.readouterr().err
    assert "PROXMOX_HOSTS" in err, (
        f"the message does not name the variable it is about:\n{err}")
    assert "secrets_dir is not readable" in err, (
        f"the underlying failure is nowhere in the message, so the operator is told "
        f"only that something is wrong with a variable:\n{err}")
    assert "not valid JSON" not in err, (
        f"a failure that has nothing to do with JSON is reported as a JSON error, which "
        f"sends whoever reads it to check a value that parses perfectly:\n{err}")


def test_happy_path_returns_instance(monkeypatch):
    monkeypatch.setenv("SOME_REQUIRED_VALUE", "ok")
    obj = load_settings_or_exit(_Req)
    assert obj.some_required_value == "ok"
