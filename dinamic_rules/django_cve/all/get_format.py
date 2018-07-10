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

import ast

import bandit
from bandit.core import test_properties as test

FORMAT_SETTINGS = [
    'DECIMAL_SEPARATOR',
    'THOUSAND_SEPARATOR',
    'NUMBER_GROUPING',
    'FIRST_DAY_OF_WEEK',
    'MONTH_DAY_FORMAT',
    'TIME_FORMAT',
    'DATE_FORMAT',
    'DATETIME_FORMAT',
    'SHORT_DATE_FORMAT',
    'SHORT_DATETIME_FORMAT',
    'YEAR_MONTH_FORMAT',
    'DATE_INPUT_FORMATS',
    'TIME_INPUT_FORMATS',
    'DATETIME_INPUT_FORMATS',
]


@test.checks('Call')
@test.test_id('CVE-2015-8213')
def get_format_used(context):
    """**CVE008: CVE-2015-8213: Test for the use of get_format**

    The get_format function in utils/formats.py in Django before 1.7.x before
    1.7.11, 1.8.x before 1.8.7, and 1.9.x before 1.9rc2 might allow remote
    attackers to obtain sensitive application secrets via a settings key in
    place of a date/time format setting, as demonstrated by SECRET_KEY.

    .. seealso::

     - https://www.cvedetails.com/django_cve/CVE-2015-8213/
     - https://www.djangoproject.com/weblog/2015/nov/
        24/security-releases-issued/
     - https://github.com/django/django/commit/
        316bc3fc9437c5960c24baceb93c73f1939711e4

    .. versionadded:: 1.4.1

    """
    description = "Use of get_format affected by CVE-2015-8213."
    affected_functions = [
        'django.utils.formats.get_format',
        'django.views.i18n.get_format',
        'django.forms.extras.widgets.get_format'
    ]
    if context.call_function_name_qual in affected_functions:
        if context.node.args:
            format_type = context.node.args[0]
            if not isinstance(format_type, ast.Str):
                return bandit.Issue(
                    severity=bandit.MEDIUM,
                    confidence=bandit.HIGH,
                    text=description
                )
            elif format_type.s not in FORMAT_SETTINGS:
                return bandit.Issue(
                    severity=bandit.MEDIUM,
                    confidence=bandit.HIGH,
                    text=description
                )
