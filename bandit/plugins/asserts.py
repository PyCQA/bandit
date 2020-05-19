# -*- coding:utf-8 -*-
#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0

r"""
============================
B101: Test for use of assert
============================

This plugin test checks for the use of the Python ``assert`` keyword. It was
discovered that some projects used assert to enforce interface constraints.
However, assert is removed with compiling to optimised byte code (python -o
producing \*.pyo files). This caused various protections to be removed. The use
of assert is also considered as general bad practice in OpenStack codebases.

Please see
https://docs.python.org/3/reference/simple_stmts.html#the-assert-statement for
more info on ``assert``

:Example:

.. code-block:: none

    >> Issue: Use of assert detected. The enclosed code will be removed when
       compiling to optimised byte code.
       Severity: Low   Confidence: High
       Location: ./examples/assert.py:1
    1 assert logged_in
    2 display_assets()

.. seealso::

 - https://bugs.launchpad.net/juniperopenstack/+bug/1456193
 - https://bugs.launchpad.net/heat/+bug/1397883
 - https://docs.python.org/3/reference/simple_stmts.html#the-assert-statement

.. versionadded:: 0.11.0

"""

import bandit
from bandit.core.issue import Cwe as Cwe
from bandit.core import test_properties as test


@test.test_id('B101')
@test.checks('Assert')
def assert_used(context):
    return bandit.Issue(
        severity=bandit.LOW,
        cwe=Cwe.IMPROPER_CHECK_OF_EXEPT_COND,
        confidence=bandit.HIGH,
        text=("Use of assert detected. The enclosed code "
              "will be removed when compiling to optimised byte code.")
    )
