#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0
r"""
=============================================
B501: Test for missing certificate validation
=============================================

Encryption in general is typically critical to the security of many
applications.  Using TLS can greatly increase security by guaranteeing the
identity of the party you are communicating with.  This is accomplished by one
or both parties presenting trusted certificates during the connection
initialization phase of TLS.

When HTTPS request methods are used, certificates are validated automatically
which is the desired behavior.  If certificate validation is explicitly turned
off Bandit will return a HIGH severity error.


:Example:

.. code-block:: none

    >> Issue: [request_with_no_cert_validation] Call to requests with
    verify=False disabling SSL certificate checks, security issue.
       Severity: High   Confidence: High
       CWE: CWE-295 (https://cwe.mitre.org/data/definitions/295.html)
       Location: examples/requests-ssl-verify-disabled.py:4
    3   requests.get('https://gmail.com', verify=True)
    4   requests.get('https://gmail.com', verify=False)
    5   requests.post('https://gmail.com', verify=True)

.. seealso::

 - https://security.openstack.org/guidelines/dg_move-data-securely.html
 - https://security.openstack.org/guidelines/dg_validate-certificates.html
 - https://cwe.mitre.org/data/definitions/295.html

.. versionadded:: 0.9.0

.. versionchanged:: 1.7.3
    CWE information added

.. versionchanged:: 1.7.5
    Added check for httpx module

"""
import ast

import bandit
from bandit.core import issue
from bandit.core import test_properties as test
from bandit.core import utils


HTTP_VERBS = {"get", "options", "head", "post", "put", "patch", "delete"}
HTTPX_ATTRS = {"request", "stream", "Client", "AsyncClient"} | HTTP_VERBS
REQUESTS_CLIENT_FACTORIES = {"requests.Session", "requests.session"}
HTTPX_CLIENT_FACTORIES = {"httpx.Client", "httpx.AsyncClient"}


def _issue(context, qualname):
    return bandit.Issue(
        severity=bandit.HIGH,
        confidence=bandit.HIGH,
        cwe=issue.Cwe.IMPROPER_CERT_VALIDATION,
        text=f"Call to {qualname} with verify=False disabling SSL "
        "certificate checks, security issue.",
        lineno=context.get_lineno_for_call_arg("verify"),
    )


def _call_name(context, node):
    return utils.get_call_name(
        node, context._context.get("import_aliases", {})
    )


def _client_factory_module(context, node):
    if not isinstance(node, ast.Call):
        return None

    call_name = _call_name(context, node)
    if call_name in REQUESTS_CLIENT_FACTORIES:
        return "requests"
    if call_name in HTTPX_CLIENT_FACTORIES:
        return "httpx"
    return None


def _target_contains_name(target, name):
    if isinstance(target, ast.Name):
        return target.id == name
    if isinstance(target, (ast.Tuple, ast.List)):
        return any(_target_contains_name(elt, name) for elt in target.elts)
    return False


def _assigned_client_module(context, name):
    parent = context.node._bandit_parent
    while parent is not None and not isinstance(
        parent, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)
    ):
        if isinstance(parent, (ast.With, ast.AsyncWith)):
            for item in parent.items:
                if item.optional_vars is not None and _target_contains_name(
                    item.optional_vars, name
                ):
                    module = _client_factory_module(context, item.context_expr)
                    if module is not None:
                        return module
        parent = getattr(parent, "_bandit_parent", None)

    if parent is None:
        return None

    module = None
    for statement in parent.body:
        if getattr(statement, "lineno", 0) >= context.node.lineno:
            break

        for node in ast.walk(statement):
            if getattr(node, "lineno", 0) >= context.node.lineno:
                continue

            if isinstance(node, ast.Assign) and any(
                _target_contains_name(target, name) for target in node.targets
            ):
                module = _client_factory_module(context, node.value)
            elif isinstance(node, ast.AnnAssign) and _target_contains_name(
                node.target, name
            ):
                module = _client_factory_module(context, node.value)

    return module


def _session_call_module(context):
    if context.call_function_name not in HTTP_VERBS:
        return None

    func = context.node.func
    if not isinstance(func, ast.Attribute) or not isinstance(
        func.value, ast.Name
    ):
        return None

    return _assigned_client_module(context, func.value.id)


@test.checks("Call")
@test.test_id("B501")
def request_with_no_cert_validation(context):
    qualname = context.call_function_name_qual.split(".")[0]

    if (
        qualname == "requests"
        and context.call_function_name in HTTP_VERBS
        or qualname == "httpx"
        and context.call_function_name in HTTPX_ATTRS
    ):
        if context.check_call_arg_value("verify", "False"):
            return _issue(context, qualname)

    session_module = _session_call_module(context)
    if session_module is not None and context.check_call_arg_value(
        "verify", "False"
    ):
        return _issue(context, session_module)
