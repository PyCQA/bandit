import functools
import re
import tomllib
from pathlib import Path

import bandit
from bandit.core import issue
from bandit.core import test_properties as test

_UNMATCHABLE_REGEX = re.compile(r"\b\B")

_config_filename = "secrets.toml"


@functools.cache
def _get_ignore_list(filename: str = _config_filename) -> list[re.Pattern]:
    with Path(__file__).with_name(filename).open("rb") as f:
        contents = tomllib.load(f)

    # Compile the reject rules into regex patterns
    return [re.compile(rule) for rule in contents.get("reject-rules", [])]


class _Secret:
    id: str  # unique identifier for the secret
    description: str  # description of the secret
    regex: re.Pattern  # compiled regex pattern for the secret
    severity: str  # severity level

    def __init__(self, id: str, description: str, regex: str, severity: str):
        self.id = id
        self.description = description
        self.regex = re.compile(regex) if regex else _UNMATCHABLE_REGEX
        self.severity = severity


_GENERIC_SECRET = _Secret(
    "generic", "Generic secret", regex="", severity="high"
)


def _make_issue(secret_spec: _Secret):
    return bandit.Issue(
        severity=bandit.HIGH,  # severity is always high -> any leaked keys are critically bad
        confidence=bandit.MEDIUM,  # and confidence is always medium
        cwe=issue.Cwe.HARDCODED_SECRETS,
        text=f"{secret_spec.id} ({secret_spec.description}) secret is stored in a string.",
    )


@functools.cache
def _get_database(filename: str = _config_filename) -> list[_Secret]:
    with Path(__file__).with_name(filename).open("rb") as f:
        contents = tomllib.load(f)

    # contents is {'rules': [{'id': ..., 'description': ..., 'regex': ..., 'severity': ...}, ...]}
    rules = contents.get("rules", [])
    db = [
        _Secret(
            rule["id"], rule["description"], rule["regex"], rule["severity"]
        )
        for rule in rules
    ]

    # remove all the secrets that are unmatchable
    db = [secret for secret in db if secret.regex != _UNMATCHABLE_REGEX]
    return db


def _is_ignored(string_to_check: str) -> bool:
    # check if the string matches any ignore pattern
    for pattern in _get_ignore_list():
        if re.search(pattern, string_to_check):
            return True
    return False


def _detect_secrets(string_to_check: str) -> list[_Secret]:
    res = []
    db = _get_database()
    for secret in db:
        matches = re.search(secret.regex, string_to_check)
        if matches is not None and not _is_ignored(matches.group()):
            res.append(secret)
    return res


@test.checks("Str")
@test.test_id("B510")
def exposed_secrets(context):
    detected_secrets = _detect_secrets(context.string_val)
    if len(detected_secrets) == 0:
        return None
    elif len(detected_secrets) == 1:
        return _make_issue(detected_secrets[0])
    else:
        return _make_issue(_GENERIC_SECRET)
