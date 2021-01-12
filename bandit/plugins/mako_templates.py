# -*- coding:utf-8 -*-
#
# SPDX-License-Identifier: Apache-2.0

r"""
====================================
B702: Test for use of mako templates
====================================

Mako is a Python templating system often used to build web applications. It is
the default templating system used in Pylons and Pyramid. Unlike Jinja2 (an
alternative templating system), Mako has no environment wide variable escaping
mechanism. Because of this, all input variables must be carefully escaped
before use to prevent possible vulnerabilities to Cross Site Scripting (XSS)
attacks.


:Example:

.. code-block:: none

    >> Issue: Mako templates allow HTML/JS rendering by default and are
    inherently open to XSS attacks. Ensure variables in all templates are
    properly sanitized via the 'n', 'h' or 'x' flags (depending on context).
    For example, to HTML escape the variable 'data' do ${ data |h }.
       Severity: Medium   Confidence: High
       Location: ./examples/mako_templating.py:10
    9
    10  mako.template.Template("hern")
    11  template.Template("hern")


.. seealso::

 - https://www.makotemplates.org/
 - `OWASP XSS <https://owasp.org/www-community/attacks/xss/>`_
 - https://security.openstack.org/guidelines/dg_cross-site-scripting-xss.html

.. versionadded:: 0.10.0

"""

import bandit
from bandit.core import test_properties as test


@test.checks('Call')
@test.test_id('B702')
def use_of_mako_templates(context):
    # check type just to be safe
    if isinstance(context.call_function_name_qual, str):
        qualname_list = context.call_function_name_qual.split('.')
        func = qualname_list[-1]
        if 'mako' in qualname_list and func == 'Template':
            # unlike Jinja2, mako does not have a template wide autoescape
            # feature and thus each variable must be carefully sanitized.
            return bandit.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.HIGH,
                text="Mako templates allow HTML/JS rendering by default and "
                     "are inherently open to XSS attacks. Ensure variables "
                     "in all templates are properly sanitized via the 'n', "
                     "'h' or 'x' flags (depending on context). For example, "
                     "to HTML escape the variable 'data' do ${ data |h }."
            )
