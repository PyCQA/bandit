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
@test.test_id('CVE-DJ-SAFE-URL')
def is_safe_url_used(context):
    r"""**CVE005: Test for the use of is_safe_url**

    Related to CVE-2013-6044, CVE-2014-3730, CVE-2015-0220, CVE-2015-2317

    The is_safe_url function in utils/http.py in Django 1.4.x before 1.4.6,
    1.5.x before 1.5.2, and 1.6 before beta 2 treats a URL's scheme as safe
    even if it is not HTTP or HTTPS, which might introduce cross-site
    scripting (XSS) or other vulnerabilities into Django applications that
    use this function, as demonstrated by "the login view in
    django.contrib.auth.views" and the javascript: scheme.

    The django.util.http.is_safe_url function in Django 1.4 before 1.4.13, 1.5
    before 1.5.8, 1.6 before 1.6.5, and 1.7 before 1.7b4 does not properly
    validate URLs, which allows remote attackers to conduct open redirect
    attacks via a malformed URL, as demonstrated by
    "http:\\\djangoproject.com."

    The django.util.http.is_safe_url function in Django before 1.4.18, 1.6.x
    before 1.6.10, and 1.7.x before 1.7.3 does not properly handle leading
    whitespaces, which allows remote attackers to conduct cross-site scripting
    (XSS) attacks via a crafted URL, related to redirect URLs, as demonstrated
    by a "\njavascript:" URL.

    The utils.http.is_safe_url function in Django before 1.4.20, 1.5.x, 1.6.x
    before 1.6.11, 1.7.x before 1.7.7, and 1.8.x before 1.8c1 does not
    properly validate URLs, which allows remote attackers to conduct
    cross-site scripting (XSS) attacks via a control character in a URL,
    as demonstrated by a \x08javascript: URL.

    .. seealso::

     - https://www.cvedetails.com/django_cve/CVE-2013-6044/
     - https://www.cvedetails.com/django_cve/CVE-2014-3730/
     - https://www.cvedetails.com/django_cve/CVE-2015-0220/
     - https://www.cvedetails.com/django_cve/CVE-2015-2317/

     - https://github.com/django/django/commit/
        2342693b31f740a422abf7267c53b4e7bc487c1b
     - https://github.com/django/django/commit/
        ec67af0bd609c412b76eaa4cc89968a2a8e5ad6a
     - https://github.com/django/django/commit/
        7feb54bbae3f637ab3c4dd4831d4385964f574df
     - https://github.com/django/django/commit/
        4c241f1b710da6419d9dca160e80b23b82db7758

    .. versionadded:: 1.4.1

    """
    desc = "Use of is_safe_url affected by" \
           " CVE-2013-6044, CVE-2014-3730, CVE-2015-0220, CVE-2015-2317."

    affected_functions = [
        'django.utils.http.is_safe_url',
        'django.contrib.comments.views.utils.is_safe_url',
        'django.contrib.auth.views.is_safe_url',
        'django.views.i18n.is_safe_url',
    ]
    # Detect also possible bypass
    if context.call_function_name_qual in affected_functions:
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.MEDIUM,
            text=desc
        )
