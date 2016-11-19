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

r"""
===================================================
B108: Test for insecure usage of tmp file/directory
===================================================

Safely creating a temporary file or directory means following a number of rules
(see the references for more details). This plugin test looks for strings
starting with (configurable) commonly used temporary paths, for example:

 - /tmp
 - /var/tmp
 - /dev/shm
 - etc

**Config Options:**

This test plugin takes a similarly named config block,
`hardcoded_tmp_directory`. The config block provides a Python list, `tmp_dirs`,
that lists string fragments indicating possible temporary file paths. Any
string starting with one of these fragments will report a MEDIUM confidence
issue.

.. code-block:: yaml

    hardcoded_tmp_directory:
        tmp_dirs: ['/tmp', '/var/tmp', '/dev/shm']


:Example:

.. code-block: none

    >> Issue: Probable insecure usage of temp file/directory.
       Severity: Medium   Confidence: Medium
       Location: ./examples/hardcoded-tmp.py:1
    1 f = open('/tmp/abc', 'w')
    2 f.write('def')

.. seealso::

 - https://security.openstack.org/guidelines/dg_using-temporary-files-securely.html  # noqa

.. versionadded:: 0.9.0

"""

import bandit
from bandit.core import test_properties as test


def gen_config(name):
    if name == 'hardcoded_tmp_directory':
        return {'tmp_dirs': ['/tmp', '/var/tmp', '/dev/shm']}


@test.takes_config
@test.checks('Str')
@test.test_id('B108')
def hardcoded_tmp_directory(context, config):
    if config is not None and 'tmp_dirs' in config:
        tmp_dirs = config['tmp_dirs']
    else:
        tmp_dirs = ['/tmp', '/var/tmp', '/dev/shm']

    if any(context.string_val.startswith(s) for s in tmp_dirs):
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.MEDIUM,
            text="Probable insecure usage of temp file/directory."
        )
