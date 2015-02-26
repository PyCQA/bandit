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

from collections import namedtuple
from distutils.sysconfig import get_python_lib
import os


# default output text colors
color = {
    'DEFAULT': '\033[0m',
    'HEADER': '\033[95m',
    'INFO': '\033[94m',
    'WARN': '\033[93m',
    'ERROR': '\033[91m',
}

# default plugin name pattern
plugin_name_pattern = '*.py'

# default progress increment
progress_increment = 50

# default plugins dir
plugins_dir = os.path.join(get_python_lib(), 'bandit', 'plugins')

# flag/s used to mark lines where identified issues should not be reported
SKIP_FLAGS = ['nosec', ]

# build skip flag re
SKIP_RE = '#\s*(({0}))$'.format(')|('.join(SKIP_FLAGS))

# list severities in ascending order
SEVERITY = ['INFO', 'WARN', 'ERROR']
SEVERITY_VALUES = {'INFO': 1, 'WARN': 5, 'ERROR': 10}

# add each severity to globals, to allow direct access in module name space
for sev in SEVERITY:
    globals()[sev] = sev

# severity level constants for assignment to individual plugins
severity_namedtuple = namedtuple('SeverityLevel', 'HIGH MEDIUM LOW')
SEVERITY_LEVEL = severity_namedtuple(HIGH=10, MEDIUM=5, LOW=0)

# confidence level constants for return from individual plugins
confidence_namedtuple = namedtuple('ConfidenceLevel', 'HIGH MEDIUM LOW')
CONFIDENCE_LEVEL = confidence_namedtuple(HIGH=10, MEDIUM=5, LOW=0)

# A list of values Python considers to be False.
# These can be useful in tests to check if a value is True or False.
# We don't handle the case of user-defined classes being false.
# These are only useful when we have a constant in code. If we
# have a variable we cannot determine if False.
# See https://docs.python.org/2/library/stdtypes.html#truth-value-testing
FALSE_VALUES = [None, False, 'False', 0, 0L, 0.0, 0j, '', (), [], {}]
