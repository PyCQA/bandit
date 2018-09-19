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
========================================
B104: Test for binding to all interfaces
========================================

Binding to all network interfaces can potentially open up a service to traffic
on unintended interfaces, that may not be properly documented or secured. This
plugin test looks for a string pattern "0.0.0.0" that may indicate a hardcoded
binding to all network interfaces.

:Example:

.. code-block:: none

    >> Issue: Possible binding to all interfaces.
       Severity: Medium   Confidence: Medium
       Location: ./examples/binding.py:4
    3   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    4   s.bind(('0.0.0.0', 31137))
    5   s.bind(('192.168.0.1', 8080))

.. seealso::

 - https://nvd.nist.gov/vuln/detail/CVE-2018-1281

.. versionadded:: 0.9.0

"""

import bandit
from bandit.core import test_properties as test


@test.checks('Str')
@test.test_id('B104')
def hardcoded_bind_all_interfaces(context):
    if context.string_val == '0.0.0.0':
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.MEDIUM,
            text="Possible binding to all interfaces."
        )
