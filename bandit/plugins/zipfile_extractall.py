# -*- coding:utf-8 -*-
#
# Copyright (c) 2018 [disconnect3d](https://github.com/disconnect3d)
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
============================================
B507: Test for use of zipfile_obj.extractall
============================================

This plugin test checks for the unsafe usage of the ``zipfile_obj.extractall``
the zipfile builtin module in old Python versions (<2.7.4, <3.3.1). The
zipfile_obj.extractall method provides the ability to create files outside of
current path, which might be dangerous if you receive a zip file from an
untrusted source.

Please see official Python docs to zipfile module for more information on
``zipfile_obj.extractall`` and ``zipfile_obj.extract``

:Example:

    >> Issue: [B507:zipfile_extractall] Use of unsafe zipfile extractall.
       Allows creation of files outside of path. Consider zipfile.extract(file).
       Severity: Medium   Confidence: Medium
       Location: examples/zipfile_extractall.py:4
    3 z = zipfile.ZipFile('some.zip')
    4 z.extractall()
    5 


.. seealso::

 - https://docs.python.org/2/library/zipfile.html#zipfile.ZipFile.extractall
 - https://docs.python.org/3.3/library/zipfile.html#zipfile.ZipFile.extractall

.. versionadded:: 1.5.0

"""

import sys
import bandit
from bandit.core import test_properties as test


@test.test_id('B507')
@test.checks('Call')
def zipfile_extractall(context):
    if sys.version_info.major == 2:
        is_old_py = sys.version_info < (2, 7, 4)
    else:
        is_old_py = sys.version_info < (3, 3, 1)

    if isinstance(context.call_function_name_qual, str):
        if is_old_py and context.is_module_imported_like('zipfile') and \
          context.call_function_name_qual.endswith('.extractall'):
            return bandit.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.MEDIUM,
                text="Use of unsafe zipfile extractall. Allows creation of"
                     " files outside of path. Consider zipfile.extract(file)"
                     " or updating Python to >=2.7.4 or >=3.3.1.",
                lineno=context.node.lineno,
            )
