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
@test.test_id('CVE-2012-3443')
def imagefield_used(context):
    """**CVE-2012-3443: Test for the use of ImageField**

    The django.forms.ImageField class in the form system in Django before
    1.3.2 and 1.4.x before 1.4.1 completely decompresses image data during
    image validation, which allows remote attackers to cause a denial of
    service (memory consumption) by uploading an image file.

    .. seealso::

     - https://www.cvedetails.com/django_cve/CVE-2012-3443/
     - https://www.djangoproject.com/weblog/2012/jul/
        30/security-releases-issued/
     - https://github.com/django/django/commit/
        b2eb4787a0fff9c9993b78be5c698e85108f3446

    .. versionadded:: 1.4.1

    """
    description = "Use of ImageField affected by CVE-2012-3443."
    if context.is_module_imported_like('django.forms'):
        if context.call_function_name == 'ImageField':
            return bandit.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.LOW,
                text=description
            )
