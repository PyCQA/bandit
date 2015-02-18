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

import bandit
from bandit.core.test_properties import *


@checks_strings
def hardcoded_sql_expressions(context):
    test_str = context.string_val.lower()
    if (
        (test_str.startswith('select ') and ' from ' in test_str) or
        test_str.startswith('insert into') or
        (test_str.startswith('update ') and ' set ' in test_str) or
        test_str.startswith('delete from ')
    ):
        # if sqlalchemy is not imported and it looks like they are using SQL
        # statements, mark it as a WARNING
        if not context.is_module_imported_like("sqlalchemy"):
            return(bandit.WARN, 'Possible SQL injection vector through '
                   'string-based query construction, without SQLALCHEMY use')

        # otherwise, if sqlalchemy is being used, mark it as INFO
        else:
            return(bandit.INFO, 'Possible SQL injection vector through'
                   ' string-based query construction')
