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
@test.test_id('CVE-2012-3444')
def get_image_dimensions_used(context):
    """**CVE-2012-3444: Test for the use of get_image_dimensions**

    The get_image_dimensions function in the image-handling functionality in
    Django before 1.3.2 and 1.4.x before 1.4.1 uses a constant chunk size in
    all attempts to determine dimensions, which allows remote attackers to
    cause a denial of service (process or thread consumption) via a large
    TIFF image.

    .. seealso::

     - https://www.cvedetails.com/django_cve/CVE-2012-3444/
     - https://www.djangoproject.com/weblog/2012/jul/
        30/security-releases-issued/
     - https://github.com/django/django/commit/
        9ca0ff6268eeff92d0d0ac2c315d4b6a8e229155

    .. versionadded:: 1.4.1

    """
    desc = "Use of get_image_dimensions affected by CVE-2012-3444."
    funct = context.call_function_name_qual
    if funct == 'django.core.files.images.get_image_dimensions':
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.LOW,
            text=desc
        )
