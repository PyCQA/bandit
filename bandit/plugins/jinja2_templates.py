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
==========================================
B701: Test for not auto escaping in jinja2
==========================================

Jinja2 is a Python HTML templating system. It is typically used to build web
applications, though appears in other places well, notably the Ansible
automation system. When configuring the Jinja2 environment, the option to use
autoescaping on input can be specified. When autoescaping is enabled, Jinja2
will filter input strings to escape any HTML content submitted via template
variables. Without escaping HTML input the application becomes vulnerable to
Cross Site Scripting (XSS) attacks.

Unfortunately, autoescaping is False by default. Thus this plugin test will
warn on omission of an autoescape setting, as well as an explicit setting of
false. A HIGH severity warning is generated in either of these scenarios.

:Example:

.. code-block:: none

    >> Issue: Using jinja2 templates with autoescape=False is dangerous and can
    lead to XSS. Use autoescape=True to mitigate XSS vulnerabilities.
       Severity: High   Confidence: High
       Location: ./examples/jinja2_templating.py:11
    10  templateEnv = jinja2.Environment(autoescape=False,
        loader=templateLoader)
    11  Environment(loader=templateLoader,
    12              load=templateLoader,
    13              autoescape=False)
    14

    >> Issue: By default, jinja2 sets autoescape to False. Consider using
    autoescape=True to mitigate XSS vulnerabilities.
       Severity: High   Confidence: High
       Location: ./examples/jinja2_templating.py:15
    14
    15  Environment(loader=templateLoader,
    16              load=templateLoader)
    17


.. seealso::

 - https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)
 - https://realpython.com/blog/python/primer-on-jinja-templating/
 - http://jinja.pocoo.org/docs/dev/api/#autoescaping
 - https://security.openstack.org
 - https://security.openstack.org/guidelines/dg_cross-site-scripting-xss.html

.. versionadded:: 0.10.0

"""

import ast

import bandit
from bandit.core import test_properties as test


@test.checks('Call')
@test.test_id('B701')
def jinja2_autoescape_false(context):
    # check type just to be safe
    if type(context.call_function_name_qual) == str:
        qualname_list = context.call_function_name_qual.split('.')
        func = qualname_list[-1]
        if 'jinja2' in qualname_list and func == 'Environment':
            for node in ast.walk(context.node):
                if isinstance(node, ast.keyword):
                    # definite autoescape = False
                    if (getattr(node, 'arg', None) == 'autoescape' and
                            (getattr(node.value, 'id', None) == 'False' or
                                getattr(node.value, 'value', None) is False)):
                        return bandit.Issue(
                            severity=bandit.HIGH,
                            confidence=bandit.HIGH,
                            text="Using jinja2 templates with autoescape="
                                 "False is dangerous and can lead to XSS. "
                                 "Use autoescape=True to mitigate XSS "
                                 "vulnerabilities."
                        )
                    # found autoescape
                    if getattr(node, 'arg', None) == 'autoescape':
                        if (getattr(node.value, 'id', None) == 'True' or
                                getattr(node.value, 'value', None) is True):
                            return
                        else:
                            return bandit.Issue(
                                severity=bandit.HIGH,
                                confidence=bandit.MEDIUM,
                                text="Using jinja2 templates with autoescape="
                                     "False is dangerous and can lead to XSS. "
                                     "Ensure autoescape=True to mitigate XSS "
                                     "vulnerabilities."
                            )
            # We haven't found a keyword named autoescape, indicating default
            # behavior
            return bandit.Issue(
                severity=bandit.HIGH,
                confidence=bandit.HIGH,
                text="By default, jinja2 sets autoescape to False. Consider "
                     "using autoescape=True to mitigate XSS vulnerabilities."
            )
