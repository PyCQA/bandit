# Copyright (c) 2017 VMware, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

r"""
==============
YAML Formatter
==============

This formatter outputs the issues in a yaml format.

:Example:

.. code-block:: none

    errors: []
    generated_at: '2017-03-09T22:29:30Z'
    metrics:
      _totals:
        CONFIDENCE.HIGH: 1
        CONFIDENCE.LOW: 0
        CONFIDENCE.MEDIUM: 0
        CONFIDENCE.UNDEFINED: 0
        SEVERITY.HIGH: 0
        SEVERITY.LOW: 0
        SEVERITY.MEDIUM: 1
        SEVERITY.UNDEFINED: 0
        loc: 9
        nosec: 0
      examples/yaml_load.py:
        CONFIDENCE.HIGH: 1
        CONFIDENCE.LOW: 0
        CONFIDENCE.MEDIUM: 0
        CONFIDENCE.UNDEFINED: 0
        SEVERITY.HIGH: 0
        SEVERITY.LOW: 0
        SEVERITY.MEDIUM: 1
        SEVERITY.UNDEFINED: 0
        loc: 9
        nosec: 0
    results:
    - code: '5     ystr = yaml.dump({''a'' : 1, ''b'' : 2, ''c'' : 3})\n
             6     y = yaml.load(ystr)\n7     yaml.dump(y)\n'
      filename: examples/yaml_load.py
      issue_confidence: HIGH
      issue_severity: MEDIUM
      issue_text: Use of unsafe yaml load. Allows instantiation of arbitrary
                  objects.
        Consider yaml.safe_load().
      line_number: 6
      line_range:
      - 6
      test_id: B506
      test_name: yaml_load

.. versionadded:: 1.4.1

"""
# Necessary for this formatter to work when imported on Python 2. Importing
# the standard library's yaml module conflicts with the name of this module.
from __future__ import absolute_import

import datetime
import logging
import operator
import sys

import yaml

LOG = logging.getLogger(__name__)


def report(manager, fileobj, sev_level, conf_level, lines=-1):
    '''Prints issues in YAML format

    :param manager: the bandit manager object
    :param fileobj: The output file object, which may be sys.stdout
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param lines: Number of lines to report, -1 for all
    '''

    machine_output = {'results': [], 'errors': []}
    for (fname, reason) in manager.get_skipped():
        machine_output['errors'].append({'filename': fname, 'reason': reason})

    results = manager.get_issue_list(sev_level=sev_level,
                                     conf_level=conf_level)

    collector = [r.as_dict() for r in results]

    itemgetter = operator.itemgetter
    if manager.agg_type == 'vuln':
        machine_output['results'] = sorted(collector,
                                           key=itemgetter('test_name'))
    else:
        machine_output['results'] = sorted(collector,
                                           key=itemgetter('filename'))

    machine_output['metrics'] = manager.metrics.data

    for result in machine_output['results']:
        if 'code' in result:
            code = result['code'].replace('\n', '\\n')
            result['code'] = code

    # timezone agnostic format
    TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

    time_string = datetime.datetime.utcnow().strftime(TS_FORMAT)
    machine_output['generated_at'] = time_string

    yaml.safe_dump(machine_output, fileobj, default_flow_style=False)

    if fileobj.name != sys.stdout.name:
        LOG.info("YAML output written to file: %s", fileobj.name)
