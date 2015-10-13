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

# default output text colors
color = {
    'DEFAULT': '\033[0m',
    'HEADER': '\033[95m',
    'LOW': '\033[94m',
    'MEDIUM': '\033[93m',
    'HIGH': '\033[91m',
}

# default plugin name pattern
plugin_name_pattern = '*.py'

# default progress increment
progress_increment = 50

# flag/s used to mark lines where identified issues should not be reported
SKIP_FLAGS = ['nosec', ]

RANKING = ['UNDEFINED', 'LOW', 'MEDIUM', 'HIGH']
RANKING_VALUES = {'UNDEFINED': 1, 'LOW': 3, 'MEDIUM': 5, 'HIGH': 10}
CRITERIA = [('SEVERITY', 'UNDEFINED'), ('CONFIDENCE', 'UNDEFINED')]

# add each ranking to globals, to allow direct access in module name space
for rank in RANKING:
    globals()[rank] = rank

CONFIDENCE_DEFAULT = 'UNDEFINED'

# A list of values Python considers to be False.
# These can be useful in tests to check if a value is True or False.
# We don't handle the case of user-defined classes being false.
# These are only useful when we have a constant in code. If we
# have a variable we cannot determine if False.
# See https://docs.python.org/2/library/stdtypes.html#truth-value-testing
FALSE_VALUES = [None, False, 'False', 0, 0.0, 0j, '', (), [], {}]
