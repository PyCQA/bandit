# -*- coding:utf-8 -*-
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


import bandit
from bandit.core import test_properties as test


@test.checks('Call')
@test.test_id('B704')
def internal_call_used(context):
    """**B704: Test for use of .__call__ internal function**

    This plugin test checks if a function is being call by using the using
    its internal .__call__ param. This can be used to obfuscate or hide
    usage of blacklisted funcations, such as Python's `exec` method.

    :Example:

    .. code-block:: none

        >> Issue: Use of __call__ detected.
        Severity: Medium   Confidence: High
        Location: ./examples/internal_call.py:1
        1 exec.__call__("do evil")

    .. seealso::

     - https://docs.python.org/3/reference/datamodel.html?highlight=__call__#object.__call__  # noqa
     - https://docs.python.org/2.6/reference/datamodel.html?highlight=__call__#object.__call__
     - https://www.python.org/dev/peps/pep-0578/#suggested-audit-hook-locations

    .. versionadded:: 1.6.3
    """
    if context.call_function_name_qual.endswith('.__call__'):
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.HIGH,
            text="Use of .__call__ detected."
        )
