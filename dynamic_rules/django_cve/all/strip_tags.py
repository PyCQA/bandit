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
@test.test_id('CVE-2015-2316')
def strip_tags_used(context):
    """**CVE-2015-2316: Test for the use of strip_tags**

    This plugin test checks for the use of the django.utils.html.strip_tags
    function in Django 1.6.x before 1.6.11, 1.7.x before 1.7.7, and 1.8.x
    before 1.8c1, when using certain versions of Python, allows remote
    attackers to cause a denial of service (infinite loop) by increasing
    the length of the input string.

    :Example:

    .. code-block:: none

        >> Issue: Use of django.utils.html.strip_tags detected.
           Severity: Medium   Confidence: Low
        1 strip_tags("do evil")

    .. seealso::

     - https://www.cvedetails.com/django_cve/CVE-2015-2316/
     - https://www.djangoproject.com/weblog/2015/mar/18/security-releases/
     - https://github.com/django/django/commit/
        b6b3cb9899214a23ebb0f4ebf0e0b300b0ee524f
     - https://github.com/django/django/commit/
        e63363f8e075fa8d66326ad6a1cc3391cc95cd97

    .. versionadded:: 1.4.1

    """
    description = "Use of strip_tags affected by CVE-2015-2316."
    affected_functions = [
        'django.utils.html.strip_tags',
        'django.template.defaultfilters.strip_tags'
    ]
    if context.call_function_name_qual in affected_functions:
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.LOW,
            text=description
        )
