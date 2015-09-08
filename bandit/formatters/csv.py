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

from __future__ import absolute_import
import csv


def report(manager, filename, sev_level, conf_level, lines=-1,
           out_format='csv'):
    '''Prints issues in CSV format

    :param manager: the bandit manager object
    :param filename: The output file name, or None for stdout
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param lines: Number of lines to report, -1 for all
    :param out_format: The ouput format name
    '''

    results = manager.get_issue_list()

    if filename is None:
        filename = 'bandit_results.csv'

    with open(filename, 'w') as fout:
        fieldnames = ['filename',
                      'test_name',
                      'issue_severity',
                      'issue_confidence',
                      'issue_text',
                      'line_number',
                      'line_range']

        writer = csv.DictWriter(fout, fieldnames=fieldnames,
                                extrasaction='ignore')
        writer.writeheader()
        for result in results:
            if result.filter(sev_level, conf_level):
                writer.writerow(result.as_dict(with_code=False))

    print("CSV output written to file: %s" % filename)
