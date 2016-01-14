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
==============================================
B601: Test for shell injection within Paramiko
==============================================

Paramiko is a Python library designed to work with the SSH2 protocol for secure
(encrypted and authenticated) connections to remote machines. It is intended to
run commands on a remote host. These commands are run within a shell on the
target and are thus vulnerable to various shell injection attacks. Bandit
reports a MEDIUM issue when it detects the use of Paramiko's "exec_command" or
"invoke_shell" methods advising the user to check inputs are correctly
sanitized.

:Example:

.. code-block:: none

    >> Issue: Possible shell injection via Paramiko call, check inputs are
       properly sanitized.
       Severity: Medium   Confidence: Medium
       Location: ./examples/paramiko_injection.py:4
    3    # this is not safe
    4    paramiko.exec_command('something; reallly; unsafe')
    5

    >> Issue: Possible shell injection via Paramiko call, check inputs are
       properly sanitized.
       Severity: Medium   Confidence: Medium
       Location: ./examples/paramiko_injection.py:10
    9    # this is not safe
    10   SSHClient.invoke_shell('something; bad; here\n')
    11

.. seealso::

 - https://security.openstack.org
 - https://github.com/paramiko/paramiko
 - https://www.owasp.org/index.php/Command_Injection

.. versionadded:: 0.12.0

"""

import bandit
from bandit.core import test_properties as test


@test.checks('Call')
@test.test_id('B601')
def paramiko_calls(context):
    issue_text = ('Possible shell injection via Paramiko call, check inputs '
                  'are properly sanitized.')
    for module in ['paramiko']:
        if context.is_module_imported_like(module):
            if context.call_function_name in ['exec_command', 'invoke_shell']:
                return bandit.Issue(severity=bandit.MEDIUM,
                                    confidence=bandit.MEDIUM,
                                    text=issue_text)
