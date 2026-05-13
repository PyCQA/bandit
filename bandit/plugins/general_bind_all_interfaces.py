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
plugin test looks for a string pattern ``"0.0.0.0"`` that may indicate a
hardcoded binding to all network interfaces, and also for ``bind`` calls whose
host argument is the empty string ``""`` -- which the Python socket API treats
as ``INADDR_ANY`` (equivalent to ``"0.0.0.0"``).

:Example:

.. code-block:: none

    >> Issue: Possible binding to all interfaces.
       Severity: Medium   Confidence: Medium
       CWE: CWE-605 (https://cwe.mitre.org/data/definitions/605.html)
       Location: ./examples/binding.py:4
    3   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    4   s.bind(('0.0.0.0', 31137))
    5   s.bind(('192.168.0.1', 8080))
    6   s.bind(('', 31137))

.. seealso::

 - https://nvd.nist.gov/vuln/detail/CVE-2018-1281
 - https://cwe.mitre.org/data/definitions/605.html
 - https://docs.python.org/3/library/socket.html#socket-families

.. versionadded:: 0.9.0

.. versionchanged:: 1.7.3
    CWE information added

.. versionchanged:: 1.9.5
    Detect ``bind(("", port))`` -- empty string resolves to ``INADDR_ANY``.

"""
import bandit
from bandit.core import issue
from bandit.core import test_properties as test


def _is_empty_string_bind(context):
    # The empty string is a Python-socket idiom for INADDR_ANY (it also acts
    # as the IPv6 wildcard via getaddrinfo), and so has the same exposure as
    # binding to "0.0.0.0". A bare "" literal is far too common to flag
    # broadly without an unreasonable false-positive rate, so this check is
    # scoped to calls named ``bind`` whose first argument is an address
    # tuple/list with "" as its host element.
    if context.call_function_name != "bind":
        return False
    if not context.call_args_count:
        return False
    address = context.get_call_arg_at_position(0)
    if not isinstance(address, (tuple, list)) or not address:
        return False
    return address[0] == ""


@test.checks("Str", "Call")
@test.test_id("B104")
def hardcoded_bind_all_interfaces(context):
    # context.string_val is populated only for Str nodes; for Call nodes the
    # plugin dispatches on the call's function name and argument shape.
    if context.string_val == "0.0.0.0":  # nosec: B104
        flagged = True
    else:
        flagged = _is_empty_string_bind(context)

    if flagged:
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.MEDIUM,
            cwe=issue.Cwe.MULTIPLE_BINDS,
            text="Possible binding to all interfaces.",
        )
