# Copyright (c) 2018 Accenture
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
=========================================
B415 Test for the usage of pyghmi library
=========================================

Warn the usage of pyghmi as IPMI is known to be a non-secure protocol.

:Example:

.. code-block:: none

        >> Issue: [B415:pyghmi] Usage of pyghmi library detected.
           IPMI is known to be a non-secure protocol.
           Severity: Medium   Confidence: Medium
           Location: examples/pyghmi.py:4
           3
           4	cmd = command.Command(bmc="bmc",
           5	                      userid="userid",
           6	                      password="ZjE4ZjI0NTE4YmI2NGJjd")

.. seealso::

    - https://www.us-cert.gov/ncas/alerts/TA13-207A

.. versionadded:: 1.5.0

"""

import bandit
from bandit.core import test_properties as test


@test.checks('Call')
@test.test_id('B415')
def pyghmi(context):
    issue_text = ('Usage of pyghmi library detected. '
                  'IPMI is known to be a non-secure protocol.')
    for module in ['pyghmi']:
        if context.is_module_imported_like(module):
            return bandit.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.MEDIUM,
                text=issue_text)
