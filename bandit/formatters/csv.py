# -*- coding:utf-8 -*-
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
=============
CSV Formatter
=============

This formatter outputs the issues in a comma separated values format.

:Example:

.. code-block:: none

    filename,test_name,test_id,issue_severity,issue_confidence,issue_text,
    line_number,line_range
    examples/yaml_load.py,blacklist_calls,B301,MEDIUM,HIGH,"Use of unsafe yaml
    load. Allows instantiation of arbitrary objects. Consider yaml.safe_load().
    ",5,[5]

.. versionadded:: 0.11.0

"""
# Necessary for this formatter to work when imported on Python 2. Importing
# the standard library's csv module conflicts with the name of this module.
from __future__ import absolute_import

import csv
import logging
import sys

LOG = logging.getLogger(__name__)


def report(manager, fileobj, sev_level, conf_level, lines=-1):
    '''Prints issues in CSV format

    :param manager: the bandit manager object
    :param fileobj: The output file object, which may be sys.stdout
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param lines: Number of lines to report, -1 for all
    '''

    results = manager.get_issue_list(sev_level=sev_level,
                                     conf_level=conf_level)

    with fileobj:
        fieldnames = ['filename',
                      'test_name',
                      'test_id',
                      'issue_severity',
                      'issue_confidence',
                      'issue_text',
                      'line_number',
                      'line_range']

        writer = csv.DictWriter(fileobj, fieldnames=fieldnames,
                                extrasaction='ignore')
        writer.writeheader()
        for result in results:
            writer.writerow(result.as_dict(with_code=False))

    if fileobj.name != sys.stdout.name:
        LOG.info("CSV output written to file: %s", fileobj.name)
