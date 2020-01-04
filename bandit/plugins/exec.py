# -*- coding:utf-8 -*-
#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0

r"""
==============================
B102: Test for the use of exec
==============================

This plugin test checks for the use of Python's `exec` method or keyword. The
Python docs succinctly describe why the use of `exec` is risky.

:Example:

.. code-block:: none

    >> Issue: Use of exec detected.
       Severity: Medium   Confidence: High
       Location: ./examples/exec-py2.py:2
    1 exec("do evil")
    2 exec "do evil"

.. seealso::

 - https://docs.python.org/2/reference/simple_stmts.html#exec
 - https://docs.python.org/3/library/functions.html#exec
 - https://www.python.org/dev/peps/pep-0551/#background
 - https://www.python.org/dev/peps/pep-0578/#suggested-audit-hook-locations

.. versionadded:: 0.9.0
"""

import six

import bandit
from bandit.core import test_properties as test


def exec_issue():
    return bandit.Issue(
        severity=bandit.MEDIUM,
        confidence=bandit.HIGH,
        text="Use of exec detected."
    )


if six.PY2:
    @test.checks('Exec')
    @test.test_id('B102')
    def exec_used(context):
        return exec_issue()
else:
    @test.checks('Call')
    @test.test_id('B102')
    def exec_used(context):
        if context.call_function_name_qual == 'exec':
            return exec_issue()
