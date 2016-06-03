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
==============
JSON formatter
==============

This formatter outputs the issues in JSON.

:Example:

.. code-block:: javascript

    {
      "errors": [],
      "generated_at": "2015-12-16T22:27:34Z",
      "metrics": {
        "_totals": {
          "CONFIDENCE.HIGH": 1,
          "CONFIDENCE.LOW": 0,
          "CONFIDENCE.MEDIUM": 0,
          "CONFIDENCE.UNDEFINED": 0,
          "SEVERITY.HIGH": 0,
          "SEVERITY.LOW": 0,
          "SEVERITY.MEDIUM": 1,
          "SEVERITY.UNDEFINED": 0,
          "loc": 5,
          "nosec": 0
        },
        "examples/yaml_load.py": {
          "CONFIDENCE.HIGH": 1,
          "CONFIDENCE.LOW": 0,
          "CONFIDENCE.MEDIUM": 0,
          "CONFIDENCE.UNDEFINED": 0,
          "SEVERITY.HIGH": 0,
          "SEVERITY.LOW": 0,
          "SEVERITY.MEDIUM": 1,
          "SEVERITY.UNDEFINED": 0,
          "loc": 5,
          "nosec": 0
        }
      },
      "results": [
        {
          "code": "4     ystr = yaml.dump({'a' : 1, 'b' : 2, 'c' : 3})\n5
                         y = yaml.load(ystr)\n6     yaml.dump(y)\n",
          "filename": "examples/yaml_load.py",
          "issue_confidence": "HIGH",
          "issue_severity": "MEDIUM",
          "issue_text": "Use of unsafe yaml load. Allows instantiation of
                         arbitrary objects. Consider yaml.safe_load().\n",
          "line_number": 5,
          "line_range": [
            5
          ],
          "test_name": "blacklist_calls",
          "test_id": "B301"
        }
      ],
      "stats": [
        {
          "filename": "examples/yaml_load.py",
          "issue totals": {
            "HIGH": 0,
            "LOW": 0,
            "MEDIUM": 1,
            "UNDEFINED": 0
          },
          "score": {
            "CONFIDENCE": 10,
            "SEVERITY": 5
          }
        }
      ]
    }

.. versionadded:: 0.10.0

"""
# Necessary so we can import the standard library json module while continuing
# to name this file json.py. (Python 2 only)
from __future__ import absolute_import

import datetime
import json
import logging
from operator import itemgetter
import sys

import six

from bandit.core import constants
from bandit.core.test_properties import accepts_baseline

logger = logging.getLogger(__name__)


@accepts_baseline
def report(manager, fileobj, sev_level, conf_level, lines=-1):
    '''''Prints issues in JSON format

    :param manager: the bandit manager object
    :param fileobj: The output file object, which may be sys.stdout
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param lines: Number of lines to report, -1 for all
    '''

    stats = dict(zip(manager.files_list, manager.scores))
    machine_output = dict({'results': [], 'errors': [], 'stats': []})
    for (fname, reason) in manager.skipped:
        machine_output['errors'].append({'filename': fname,
                                         'reason': reason})

    for filer, score in six.iteritems(stats):
        totals = {}
        rank = constants.RANKING
        sev_idx = rank.index(sev_level)
        for i in range(sev_idx, len(rank)):
            severity = rank[i]
            severity_value = constants.RANKING_VALUES[severity]
            try:
                sc = score['SEVERITY'][i] / severity_value
            except ZeroDivisionError:
                sc = 0
            totals[severity] = sc

        machine_output['stats'].append({
            'filename': filer,
            'score': {'SEVERITY': sum(i for i in score['SEVERITY']),
                      'CONFIDENCE': sum(i for i in score['CONFIDENCE'])},
            'issue totals': totals})

    results = manager.get_issue_list(sev_level=sev_level,
                                     conf_level=conf_level)

    baseline = not isinstance(results, list)

    if baseline:
        collector = []
        for r in results:
            d = r.as_dict()
            if len(results[r]) > 1:
                d['candidates'] = [c.as_dict() for c in results[r]]
            collector.append(d)

    else:
        collector = [r.as_dict() for r in results]

    if manager.agg_type == 'vuln':
        machine_output['results'] = sorted(collector,
                                           key=itemgetter('test_name'))
    else:
        machine_output['results'] = sorted(collector,
                                           key=itemgetter('filename'))

    machine_output['metrics'] = manager.metrics.data

    # timezone agnostic format
    TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

    time_string = datetime.datetime.utcnow().strftime(TS_FORMAT)
    machine_output['generated_at'] = time_string

    result = json.dumps(machine_output, sort_keys=True,
                        indent=2, separators=(',', ': '))

    with fileobj:
        fileobj.write(result)

    if fileobj.name != sys.stdout.name:
        logger.info("JSON output written to file: %s" % fileobj.name)
