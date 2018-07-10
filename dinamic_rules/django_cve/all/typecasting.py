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
@test.test_id('CVE-2014-0474')
def typecasting_attack(context):
    """**CVE004: CVE-2014-0474**

    The (1) FilePathField, (2) GenericIPAddressField, and (3) IPAddressField
    model field classes in Django before 1.4.11, 1.5.x before 1.5.6, 1.6.x
    before 1.6.3, and 1.7.x before 1.7 beta 2 do not properly perform type
    conversion, which allows remote attackers to have unspecified impact and
    vectors, related to "MySQL typecasting."

    .. seealso::

     - https://www.cvedetails.com/django_cve/CVE-2014-0474/
     - https://www.djangoproject.com/weblog/2014/apr/21/security/
     - https://github.com/django/django/commit/
        aa80f498de6d687e613860933ac58433ab71ea4b

    .. versionadded:: 1.4.1

    """
    description = "Possible MySQL typecasting check CVE-2014-0474."
    # Include django.db.model and django.db.model.fields
    affected_classes = [
        'FilePathField',
        'GenericIPAddressField',
        'IPAddressField',
    ]
    if context.is_module_imported_like('django.db.model'):
        if context.call_function_name in affected_classes:
            return bandit.Issue(
                severity=bandit.HIGH,
                confidence=bandit.HIGH,
                text=description
            )
