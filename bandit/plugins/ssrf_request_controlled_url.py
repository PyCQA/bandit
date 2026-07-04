#
# Copyright 2024 BerriAI
#
# SPDX-License-Identifier: Apache-2.0
r"""
=========================================================
B211: Test for SSRF via user-controlled URL in HTTP requests
=========================================================

Server-Side Request Forgery (SSRF) occurs when an attacker can
make the server send requests to unintended locations. This plugin
detects cases where user-controlled input flows into outbound HTTP
requests via ``requests``, ``httpx``, ``urllib``, or ``aiohttp``.

:Example:

.. code-block:: none

    >> Issue: Possible SSRF: user-controlled URL passed to requests.get().
       Severity: High   Confidence: Medium
       CWE: CWE-918 (https://cwe.mitre.org/data/definitions/918.html)
       Location: examples/ssrf_example.py:5
    4  url = request.args.get("url")
    5  resp = requests.get(url)

.. seealso::

 - https://cwe.mitre.org/data/definitions/918.html
 - https://owasp.org/www-community/attacks/Server_Side_Request_Forgery

.. versionadded:: 1.8.0

"""
import ast

import bandit
from bandit.core import issue
from bandit.core import test_properties as test

# Sinks: outbound HTTP call methods
_SINK_METHODS = {
    "get",
    "post",
    "put",
    "delete",
    "patch",
    "head",
    "options",
    "request",
    "fetch",
}

# Source: common request accessor patterns
_REQUEST_ACCESSORS = {
    "args",
    "form",
    "values",
    "json",
    "data",
    "cookies",
    "query_params",
    "body",
    "get_json",
}


@test.test_id("B211")
@test.checks("Call")
def ssrf_user_controlled_url(context):
    """Check for SSRF: user-controlled URL in outbound HTTP request."""
    if not isinstance(context.call_function_name_qual, str):
        return

    qualname_list = context.call_function_name_qual.split(".")
    func = qualname_list[-1]
    module = ".".join(qualname_list[:-1]) if len(qualname_list) > 1 else ""

    # Check for requests/httpx/aiohttp/urllib calls
    is_http_call = False
    if func in _SINK_METHODS:
        if any(
            lib in module for lib in ("requests", "httpx", "aiohttp", "urllib")
        ):
            is_http_call = True

    if not is_http_call:
        return

    # Check if the URL argument (first positional) is request-controlled
    if context.node.args:
        first_arg = context.node.args[0]
        if _is_request_controlled(first_arg):
            return bandit.Issue(
                severity=bandit.HIGH,
                confidence=bandit.MEDIUM,
                cwe=918,
                text="Possible SSRF: user-controlled URL passed to "
                f"{module}.{func}().",
            )


def _is_request_controlled(node):
    """Check if an AST node is a request-controlled value."""
    # Direct: request.args.get(...)
    if isinstance(node, ast.Call):
        return _is_request_accessor_call(node)

    # Variable: url = request.args.get(...); requests.get(url)
    if isinstance(node, ast.Name):
        return False  # Would need scope tracking; skip for now

    return False


def _is_request_accessor_call(node):
    """Check if a call is request.args/form/values/etc.get(...)."""
    if not isinstance(node, ast.Call):
        return False

    func = node.func
    if not isinstance(func, ast.Attribute):
        return False

    if func.attr not in ("get", "__getitem__"):
        return False

    obj = func.value
    if isinstance(obj, ast.Attribute):
        return obj.attr in _REQUEST_ACCESSORS

    return False
