#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0
r"""
========================================
B104: Test for binding to all interfaces
========================================

Binding to all network interfaces can potentially open up a service to traffic
on unintended interfaces, that may not be properly documented or secured. This
plugin test looks for a call to ``bind()`` with a wildcard host address
(``'0.0.0.0'`` or ``''``) that may indicate binding to all network interfaces.

:Example:

.. code-block:: none

    >> Issue: Possible binding to all interfaces.
       Severity: Medium   Confidence: Medium
       CWE: CWE-605 (https://cwe.mitre.org/data/definitions/605.html)
       Location: ./examples/binding.py:4
    3   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    4   s.bind(('0.0.0.0', 31137))
    5   s.bind(('', 8080))

.. seealso::

 - https://nvd.nist.gov/vuln/detail/CVE-2018-1281
 - https://cwe.mitre.org/data/definitions/605.html

.. versionadded:: 0.9.0

.. versionchanged:: 1.7.3
    CWE information added

"""
import ast

import bandit
from bandit.core import issue
from bandit.core import test_properties as test


@test.checks("Call")
@test.test_id("B104")
def hardcoded_bind_all_interfaces(context):
    if context.call_function_name != "bind":
        return

    if not context.node.args:
        return

    first_arg = context.node.args[0]

    # Check for bind(('0.0.0.0', port)) or bind(('', port))
    if isinstance(first_arg, ast.Tuple) and first_arg.elts:
        host = first_arg.elts[0]
        if isinstance(host, ast.Constant) and host.value in ("0.0.0.0", ""):
            return bandit.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.MEDIUM,
                cwe=issue.Cwe.MULTIPLE_BINDS,
                text="Possible binding to all interfaces.",
            )
