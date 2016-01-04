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
Encryption in general is typically critical to the security of many
applications.  Using TLS can greatly increase security by guaranteeing the
identity of the party you are communicating with.  This is accomplished by one
or both parties presenting trusted certificates during the connection
initialization phase of TLS.

When request methods are used certificates are validated automatically which is
the desired behavior.  If certificate validation is explicitly turned off
Bandit will return a HIGH severity error.

Config Options
--------------
None

Sample Output
-------------
.. code-block:: none

    >> Issue: [request_with_no_cert_validation] Requests call with verify=False
    disabling SSL certificate checks, security issue.
       Severity: High   Confidence: High
       Location: examples/requests-ssl-verify-disabled.py:4
    3   requests.get('https://gmail.com', verify=True)
    4   requests.get('https://gmail.com', verify=False)
    5   requests.post('https://gmail.com', verify=True)

References
----------
- https://security.openstack.org/guidelines/dg_move-data-securely.html
- https://security.openstack.org/guidelines/dg_validate-certificates.html

.. versionadded:: 0.9.0

"""

import bandit
from bandit.core import test_properties as test


@test.checks('Call')
@test.test_id('B501')
def request_with_no_cert_validation(context):
    http_verbs = ('get', 'options', 'head', 'post', 'put', 'patch', 'delete')
    if ('requests' in context.call_function_name_qual and
            context.call_function_name in http_verbs):
        if context.check_call_arg_value('verify', 'False'):
            issue = bandit.Issue(
                severity=bandit.HIGH,
                confidence=bandit.HIGH,
                text="Requests call with verify=False disabling SSL "
                     "certificate checks, security issue.",
                lineno=context.get_lineno_for_call_arg('verify'),
            )
            return issue
