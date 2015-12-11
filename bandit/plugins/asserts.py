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
Description
-----------
This plugin test checks for the use of the Python ``assert`` keyword. It was
discovered that some projects used assert to enforce interface constraints.
However, assert is removed with compiling to optimised byte code (python -o
producing \*.pyo files). This caused various protections to be removed. The use
of assert is also considered as general bad practice in OpenStack codebases.

Please see
https://docs.python.org/2/reference/simple_stmts.html#the-assert-statement for
more info on ``assert``

Config Options
--------------
None

Sample Output
-------------
.. code-block:: none

    >> Issue: Use of assert detected. The enclosed code will be removed when
       compiling to optimised byte code.
       Severity: Low   Confidence: High
       Location: ./examples/assert.py:1
    1 assert logged_in
    2 display_assets()

References
----------
 - https://bugs.launchpad.net/juniperopenstack/+bug/1456193
 - https://bugs.launchpad.net/heat/+bug/1397883
 - https://docs.python.org/2/reference/simple_stmts.html#the-assert-statement

.. versionadded:: 0.11.0

"""

import bandit
from bandit.core.test_properties import *


@checks('Assert')
def assert_used(context):
        return bandit.Issue(
            severity=bandit.LOW,
            confidence=bandit.HIGH,
            text=("Use of assert detected. The enclosed code "
                  "will be removed when compiling to optimised byte code.")
        )
