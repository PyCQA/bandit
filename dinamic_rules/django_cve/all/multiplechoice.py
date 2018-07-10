# -*- coding:utf-8 -*-
#
# Copyright (c) 2017
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
@test.test_id('CVE-2015-0222')
def multiplechoice_with_hidden_used(context):
    """**CVE006: CVE-2015-0222: Test for the use of ModelMultipleChoiceField**

    ModelMultipleChoiceField in Django 1.6.x before 1.6.10 and 1.7.x
    before 1.7.3, when show_hidden_initial is set to True, allows remote
    attackers to cause a denial of service by submitting duplicate values,
    which triggers a large number of SQL queries.

    .. seealso::

     - https://www.cvedetails.com/django_cve/CVE-2015-0222/
     - https://www.djangoproject.com/weblog/2015/jan/13/security/
     - https://github.com/django/django/commit/
        d7a06ee7e571b6dad07c0f5b519b1db02e2a476c

    .. versionadded:: 1.4.1

    """
    desc = "Use of ModelMultipleChoiceField with show_hidden_initial" \
           " affected by CVE-2015-0222."
    if context.is_module_imported_like('django.forms'):
        if context.call_function_name == 'ModelMultipleChoiceField':
            if 'show_hidden_initial' in context.call_keywords:
                if context.call_keywords['show_hidden_initial']:
                    return bandit.Issue(
                        severity=bandit.MEDIUM,
                        confidence=bandit.LOW,
                        text=desc
                    )
