# Copyright (c) 2022 Rajesh Pangare
#
# SPDX-License-Identifier: Apache-2.0
r"""
====================================================
B704: Test for use of flask.Markup
====================================================

``Markup`` accepts a string or an object that is converted
to text, and wraps it to mark it safe without escaping. Calling
``Markup`` on data submitted by users could lead to XSS.

Do not use ``Markup`` or ``Markup.unescape`` on untrusted data.
Use ``Markup.escape`` to escape unsafe HTML.

:Example:
    >> Issue: [B704:flask_markup_xss] Potential XSS
    `with `flask.Markup``. Do not use ``Markup`` or
    ``Markup.unescape`` on untrusted data. Use
    ``Markup.escape`` to escape untrusted data
       Severity: Medium   Confidence: High
       CWE: CWE-79 (https://cwe.mitre.org/data/definitions/79.html)
       Location: examples/flask_markup_xss.py:16:0
    9
    10	link = flask.Markup(user_input)

.. seealso::

 - https://flask.palletsprojects.com/en/2.0.x/api/#flask.Markup

.. versionadded:: 1.7.5

"""
import bandit
from bandit.core import issue
from bandit.core import test_properties as test


def markup_usage(context):
    if context.call_function_name_qual == "flask.Markup":
        return True
    return False


def markup_method_with_unescape(context):
    """
    To flag flask.Markup.*().unescape()
    """
    node = context.node
    try:
        if (
            node.func.attr == "unescape"
            and node.func.value.func.value.value.id == "flask"
            and node.func.value.func.value.attr == "Markup"
        ):
            return True
    except AttributeError:
        pass
    return False


@test.checks("Call")
@test.test_id("B704")
def flask_markup_xss(context):
    if markup_usage(context) or markup_method_with_unescape(context):
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.HIGH,
            cwe=issue.Cwe.XSS,
            text="Potential XSS with ``flask.Markup``. Do "
            "not use ``Markup`` or ``Markup.unescape`` "
            "on untrusted data. Use ``Markup.escape`` to "
            "escape untrusted data",
        )
