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
===============================================================
B109: Test for a password based config option not marked secret
===============================================================

Passwords are sensitive and must be protected appropriately. In OpenStack
Oslo there is an option to mark options "secret" which will ensure that they
are not logged. This plugin detects usages of oslo configuration functions
that appear to deal with strings ending in 'password' and flag usages where
they have not been marked secret.

If such a value is found a MEDIUM severity error is generated. If 'False' or
'None' are explicitly set, Bandit will return a MEDIUM confidence issue. If
Bandit can't determine the value of secret it will return a LOW confidence
issue.


**Config Options:**

.. code-block:: yaml

    password_config_option_not_marked_secret:
        function_names:
            - oslo.config.cfg.StrOpt
            - oslo_config.cfg.StrOpt

:Example:

.. code-block:: none

    >> Issue: [password_config_option_not_marked_secret] oslo config option
    possibly not marked secret=True identified.
       Severity: Medium   Confidence: Low
       Location: examples/secret-config-option.py:12
    11                  help="User's password"),
    12       cfg.StrOpt('nova_password',
    13                  secret=secret,
    14                  help="Nova user password"),
    15   ]

    >> Issue: [password_config_option_not_marked_secret] oslo config option not
    marked secret=True identified, security issue.
       Severity: Medium   Confidence: Medium
       Location: examples/secret-config-option.py:21
    20                  help="LDAP ubind ser name"),
    21       cfg.StrOpt('ldap_password',
    22                  help="LDAP bind user password"),
    23       cfg.StrOpt('ldap_password_attribute',

.. seealso::

 - https://security.openstack.org/guidelines/dg_protect-sensitive-data-in-files.html  # noqa

.. versionadded:: 0.10.0

"""

import bandit
from bandit.core import constants
from bandit.core import test_properties as test


def gen_config(name):
    if name == 'password_config_option_not_marked_secret':
        return {'function_names':
                ['oslo.config.cfg.StrOpt',
                 'oslo_config.cfg.StrOpt']}


@test.takes_config
@test.checks('Call')
@test.test_id('B109')
def password_config_option_not_marked_secret(context, config):

    if(context.call_function_name_qual in config['function_names'] and
       context.get_call_arg_at_position(0) is not None and
       context.get_call_arg_at_position(0).endswith('password')):

        # Checks whether secret=False or secret is not set (None).
        # Returns True if argument found, and matches supplied values
        # and None if argument not found at all.
        if context.check_call_arg_value('secret',
                                        constants.FALSE_VALUES) in [
                                            True, None]:
            return bandit.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.MEDIUM,
                text="oslo config option not marked secret=True "
                     "identified, security issue.",
                lineno=context.get_lineno_for_call_arg('secret'),
            )
        # Checks whether secret is not True, for example when its set to a
        # variable, secret=secret.
        elif not context.check_call_arg_value('secret', 'True'):
            return bandit.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.LOW,
                text="oslo config option possibly not marked secret=True "
                     "identified.",
                lineno=context.get_lineno_for_call_arg('secret'),
            )
