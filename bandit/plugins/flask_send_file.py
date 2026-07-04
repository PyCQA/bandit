#
# Copyright 2024 BerriAI
#
# SPDX-License-Identifier: Apache-2.0
r"""
===========================================================
B210: Test for use of Flask send_file with request-controlled path
===========================================================

Flask's ``send_file()`` function can be used to serve files from the
server. If the path argument is controlled by user input (e.g., from
``request.args``, ``request.form``, or ``request.values``), it can lead
to arbitrary file read or path traversal vulnerabilities.

:Example:

.. code-block:: none

    >> Issue: Flask send_file() called with a request-controlled path,
    which can lead to arbitrary file read or path traversal.
       Severity: High   Confidence: Medium
       CWE: CWE-22 (https://cwe.mitre.org/data/definitions/22.html)
       Location: examples/flask_send_file.py:10
    9  path = request.args.get("path")
    10 return send_file(path)

.. seealso::

 - https://flask.palletsprojects.com/en/latest/api/#flask.send_file
 - https://cwe.mitre.org/data/definitions/22.html

.. versionadded:: 1.8.0

"""
import ast

import bandit
from bandit.core import issue
from bandit.core import test_properties as test


@test.test_id("B210")
@test.checks("Call")
def flask_send_file_request_controlled(context):
    """Check for Flask send_file() called with request-controlled path."""
    if not isinstance(context.call_function_name_qual, str):
        return

    qualname_list = context.call_function_name_qual.split(".")
    func = qualname_list[-1]

    # Check for flask.send_file(...)
    if func == "send_file" and "flask" in qualname_list:
        if context.node.args:
            first_arg = context.node.args[0]

            # Check if the argument is a direct request accessor call
            if isinstance(first_arg, ast.Call):
                if _is_request_accessor_call(first_arg):
                    return bandit.Issue(
                        severity=bandit.HIGH,
                        confidence=bandit.MEDIUM,
                        cwe=issue.Cwe.PATH_TRAVERSAL,
                        text="Flask send_file() called with a "
                        "request-controlled path, which can "
                        "lead to arbitrary file read or path "
                        "traversal.",
                    )


def _is_request_accessor_call(node):
    """Check if a call node is a request.args/form/values.get(...) call."""
    if not isinstance(node, ast.Call):
        return False

    # Check if the function is .get() or similar
    func = node.func
    if not isinstance(func, ast.Attribute):
        return False

    if func.attr not in ("get", "post", "__getitem__"):
        return False

    # Check if the object is request.args, request.form, or request.values
    obj = func.value
    if isinstance(obj, ast.Attribute):
        return obj.attr in ("args", "form", "values")

    return False
