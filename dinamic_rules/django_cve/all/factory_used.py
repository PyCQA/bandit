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
@test.test_id('CVE-2013-0306')
def formset_factory_used(context):
    """**CVE003: CVE-2013-0306: Test for the use of formset_factory**

    The form library in Django 1.3.x before 1.3.6, 1.4.x before 1.4.4, and 1.5
    before release candidate 2 allows remote attackers to bypass intended
    resource limits for formsets and cause a denial of service (memory
    consumption) or trigger server errors via a modified max_num parameter.

    .. seealso::

     - https://www.cvedetails.com/django_cve/CVE-2013-0306/
     - https://www.djangoproject.com/weblog/2013/feb/19/security/
     - https://github.com/django/django/commit/
        d7094bbce8cb838f3b40f504f198c098ff1cf727
     - https://github.com/django/django/commit/
        0cc350a896f70ace18280410eb616a9197d862b0

    .. versionadded:: 1.4.1

    """
    description = "Use of formset_factory affected by CVE-2013-0306."
    if context.is_module_imported_like('django.forms'):
        if context.call_function_name == 'formset_factory':
            return bandit.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.LOW,
                text=description
            )
