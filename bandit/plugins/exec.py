# -*- coding:utf-8 -*-
#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

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

 - https://docs.python.org/2.0/ref/exec.html
 - TODO: add info on exec and similar to sec best practice and link here

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
