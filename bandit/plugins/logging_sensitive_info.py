#
# Copyright 2026 RaccoonLabs
# SPDX-License-Identifier: Apache-2.0
"""
Bandit plugin to detect logging/printing of sensitive information.

Flags calls to logging.*, print(), pprint.*, and f-string output where
the arguments contain variable names associated with secrets:
password, secret, token, api_key, private_key, credential, auth_token, etc.
"""
import ast
import re

import bandit
from bandit.core import issue
from bandit.core import test_properties as test

# Sensitive variable name patterns
RE_SENSITIVE = re.compile(
    r"(pas+wo?r?d|pass(phrase)?|pwd|secret|token|api_key|apikey|"
    r"private_key|privatekey|access_key|accesskey|secret_key|secretkey|"
    r"credential|auth_token|auth_token|bearer|api_secret|client_secret|"
    r"database_url|db_password|db_pass|encryption_key|signing_key)",
    re.IGNORECASE,
)

# Logging modules and functions to check
LOGGING_MODULES = {"logging", "logger"}
PRINT_FUNCTIONS = {
    "print",
    "pprint",
    "pprint.pprint",
    "debug",
    "info",
    "warning",
    "warn",
    "error",
    "critical",
    "exception",
    "log",
}
LOGGING_METHODS = {
    "debug",
    "info",
    "warning",
    "warn",
    "error",
    "critical",
    "exception",
    "log",
    "fatal",
}


def _is_sensitive_name(name: str) -> bool:
    """Check if a variable name looks like it holds sensitive data."""
    return bool(RE_SENSITIVE.search(name))


def _check_node_for_sensitive(node) -> list:
    """Recursively check an AST node for references to sensitive variable names."""
    found = []

    if isinstance(node, ast.Name):
        if _is_sensitive_name(node.id):
            found.append(node.id)
    elif isinstance(node, ast.Attribute):
        if _is_sensitive_name(node.attr):
            found.append(node.attr)
    elif isinstance(node, ast.Subscript):
        found.extend(_check_node_for_sensitive(node.value))
    elif isinstance(node, ast.FormattedValue):
        found.extend(_check_node_for_sensitive(node.value))
    elif isinstance(node, ast.JoinedStr):
        for value in node.values:
            found.extend(_check_node_for_sensitive(value))
    elif isinstance(node, ast.Call):
        # Check keyring.get_password() and similar
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in (
                "get_password",
                "get_credential",
                "get_secret",
            ):
                found.append(node.func.attr)
    elif isinstance(node, ast.BinOp):
        # f-string style: "Password: " + password
        found.extend(_check_node_for_sensitive(node.left))
        found.extend(_check_node_for_sensitive(node.right))
    elif isinstance(node, (ast.Tuple, ast.List)):
        for elt in node.elts:
            found.extend(_check_node_for_sensitive(elt))

    return found


def _is_logging_call(node: ast.Call) -> bool:
    """Check if a Call node is a logging or print call."""
    func = node.func

    # print(), pprint()
    if isinstance(func, ast.Name) and func.id in PRINT_FUNCTIONS:
        return True

    # logging.debug(), logger.info(), etc.
    if isinstance(func, ast.Attribute):
        if func.attr in LOGGING_METHODS:
            # Check if the object is a logger
            if isinstance(func.value, ast.Name):
                # Could be any logger instance or the logging module
                return True
            if isinstance(func.value, ast.Attribute):
                return True

    return False


@test.checks("Call")
@test.test_id("B622")
def logging_sensitive_info(context):
    """**B622: Test for logging of sensitive information**

    This plugin detects when potentially sensitive information is passed
    to logging or print calls. Sensitive variable names include:
    password, secret, token, api_key, private_key, credential, etc.

    **Config Options:**

    None

    :Example:

    .. code-block:: none

        >> Issue: [B622] Possible sensitive information logged: 'password'
           Severity: Medium   Confidence: Medium
           CWE: CWE-532 (https://cwe.mitre.org/data/definitions/532.html)
           Location: ./examples/sensitive_logging.py:5
        4 def login(user, password):
        5     logging.debug("Password: %s", password)

    .. seealso::

        - https://cwe.mitre.org/data/definitions/532.html
        - https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_parameters_in_url

    .. versionadded:: 1.9.0
    """
    node = context.node

    if not isinstance(node, ast.Call):
        return None

    if not _is_logging_call(node):
        return None

    # Check all arguments for sensitive variable references
    sensitive_found = []
    for arg in node.args:
        sensitive_found.extend(_check_node_for_sensitive(arg))

    for kw in node.keywords:
        if kw.arg and _is_sensitive_name(kw.arg):
            sensitive_found.append(kw.arg)
        sensitive_found.extend(_check_node_for_sensitive(kw.value))

    if not sensitive_found:
        return None

    # Deduplicate
    unique_sensitive = list(dict.fromkeys(sensitive_found))

    return bandit.Issue(
        severity=bandit.MEDIUM,
        confidence=bandit.MEDIUM,
        cwe=issue.Cwe.CLEARTEXT_TRANSMISSION,
        text=(
            f"Possible sensitive information in logging/print call: "
            f"'{', '.join(unique_sensitive)}'. "
            f"Avoid logging passwords, tokens, API keys, or other secrets."
        ),
    )
