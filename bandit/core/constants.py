# -*- coding:utf-8 -*-
#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os
from distutils.sysconfig import get_python_lib

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

# add each severity to globals, to allow direct access in module name space
for sev in SEVERITY:
    globals()[sev] = sev
