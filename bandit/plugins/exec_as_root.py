# Copyright (c) 2015 VMware, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

r"""
Description
-----------
Running commands as root dramatically increase their potential risk. Running
commands with restricted user privileges provides defense in depth against
command injection attacks, or developer and configuration error. This plugin
test checks for specific methods being called with a keyword parameter
`run_as_root` set to True, a common OpenStack idiom.


Config Options
--------------
This test plugin takes a similarly named configuration block,
`execute_with_run_as_root_equals_true`, providing a list, `function_names`, of
function names. A call to any of these named functions will be checked for a
`run_as_root` keyword parameter, and if True, will report a Low severity
issue.

.. code-block:: yaml

    execute_with_run_as_root_equals_true:
        function_names:
            - ceilometer.utils.execute
            - cinder.utils.execute
            - neutron.agent.linux.utils.execute
            - nova.utils.execute
            - nova.utils.trycmd


Sample Output
-------------
.. code-block:: none

    >> Issue: Execute with run_as_root=True identified, possible security
       issue.
       Severity: Low   Confidence: Medium
       Location: ./examples/exec-as-root.py:26
    25  nova_utils.trycmd('gcc --version')
    26  nova_utils.trycmd('gcc --version', run_as_root=True)
    27

References
----------
 - https://security.openstack.org/guidelines/dg_rootwrap-recommendations-and-plans.html  # noqa
 - https://security.openstack.org/guidelines/dg_use-oslo-rootwrap-securely.html

.. versionadded:: 0.10.0

"""

import bandit
from bandit.core.test_properties import *


@takes_config
@checks('Call')
def execute_with_run_as_root_equals_true(context, config):

    if (context.call_function_name_qual in config['function_names']):
        if context.check_call_arg_value('run_as_root', 'True'):
            return bandit.Issue(
                severity=bandit.LOW,
                confidence=bandit.MEDIUM,
                text="Execute with run_as_root=True identified, possible "
                     "security issue."
            )
