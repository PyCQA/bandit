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
import collections
import csv
import datetime
import json
from operator import itemgetter

import six

from bandit.core import constants


def report_csv(result_store, file_list, scores, excluded_files):
    '''Prints/returns warnings in JSON format

    :param result_store: results of scan as BanditResultStore object
    :param files_list: Which files were inspected
    :param scores: The scores awarded to each file in the scope
    :param excluded_files: Which files were excluded from the scope
    :return: A collection containing the CSV data
    '''

    results = result_store._get_issue_list()

    # Remove the code from all the issues in the list, as we will not
    # be including it in the CSV data.
    def del_code(issue):
        del issue['code']
    map(del_code, results)

    if result_store.out_file is None:
        result_store.out_file = 'bandit_results.csv'

    with open(result_store.out_file, 'w') as fout:
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
        writer.writerows(results)

    print("CSV output written to file: %s" % result_store.out_file)


def report_json(result_store, file_list, scores, excluded_files):
    '''Prints/returns warnings in JSON format

    :param result_store: results of scan as BanditResultStore object
    :param files_list: Which files were inspected
    :param scores: The scores awarded to each file in the scope
    :param excluded_files: Which files were excluded from the scope
    :return: JSON string
    '''

    stats = dict(zip(file_list, scores))

    machine_output = dict({'results': [], 'errors': [], 'stats': []})
    collector = list()
    for (fname, reason) in result_store.skipped:
        machine_output['errors'].append({'filename': fname,
                                        'reason': reason})

    for filer, score in six.iteritems(stats):
        totals = {}
        for i in range(result_store.sev_level, len(constants.RANKING)):
            severity = constants.RANKING[i]
            severity_value = constants.RANKING_VALUES[severity]
            try:
                sc = score['SEVERITY'][i] / severity_value
            except ZeroDivisionError:
                sc = 0
            totals[severity] = sc

        machine_output['stats'].append({
            'filename': filer,
            'score': result_store._sum_scores(score),
            'issue totals': totals})

    collector = result_store._get_issue_list()

    if result_store.agg_type == 'vuln':
        machine_output['results'] = sorted(collector,
                                           key=itemgetter('error_type'))
    else:
        machine_output['results'] = sorted(collector,
                                           key=itemgetter('filename'))

    # timezone agnostic format
    TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

    time_string = result_store.generated_time.strftime(TS_FORMAT)
    machine_output['generated_at'] = time_string

    result = json.dumps(machine_output, sort_keys=True,
                        indent=2, separators=(',', ': '))

    if result_store.out_file:
        with open(result_store.out_file, 'w') as fout:
            fout.write(result)
            # XXX: Should this be log output? (ukbelch)
        print("JSON output written to file: %s" % result_store.out_file)
    else:
        print(result)


def report_text(result_store, files_list, scores, excluded_files):
    '''Prints the contents of the result store

    :param result_store: results of scan as BanditResultStore object
    :param files_list: Which files were inspected
    :param scores: The scores awarded to each file in the scope
    :param excluded_files: List of files excluded from the scope
    :return: TXT string with appropriate TTY coloring for terminals
    '''

    tmpstr_list = []

    # use a defaultdict to default to an empty string
    color = collections.defaultdict(str)

    if result_store.format == 'txt':
        # get text colors from settings for TTY output
        get_setting = result_store.config.get_setting
        color = {'HEADER': get_setting('color_HEADER'),
                 'DEFAULT': get_setting('color_DEFAULT'),
                 'LOW': get_setting('color_LOW'),
                 'MEDIUM': get_setting('color_MEDIUM'),
                 'HIGH': get_setting('color_HIGH')
                 }

    # print header
    tmpstr_list.append("%sRun started:%s\n\t%s\n" % (
        color['HEADER'],
        color['DEFAULT'],
        datetime.datetime.utcnow()
    ))

    if result_store.verbose:
        # print which files were inspected
        tmpstr_list.append("\n%sFiles in scope (%s):%s\n" % (
            color['HEADER'], len(files_list),
            color['DEFAULT']
        ))

        for item in zip(files_list, map(result_store._sum_scores, scores)):
            tmpstr_list.append("\t%s (score: %i)\n" % item)

        # print which files were excluded and why
        tmpstr_list.append("\n%sFiles excluded (%s):%s\n" %
                           (color['HEADER'], len(excluded_files),
                            color['DEFAULT']))
        for fname in excluded_files:
            tmpstr_list.append("\t%s\n" % fname)

    # print which files were skipped and why
    tmpstr_list.append("\n%sFiles skipped (%s):%s\n" % (
        color['HEADER'], len(result_store.skipped),
        color['DEFAULT']
    ))

    for (fname, reason) in result_store.skipped:
        tmpstr_list.append("\t%s (%s)\n" % (fname, reason))

    # print the results
    tmpstr_list.append("\n%sTest results:%s\n" % (
        color['HEADER'], color['DEFAULT']
    ))

    if result_store.count == 0:
        tmpstr_list.append("\tNo issues identified.\n")

    for filename, issues in result_store.resstore.items():
        for issue in issues:

            # if the result isn't filtered out by severity
            if (result_store._check_severity(issue['issue_severity']) and
                    result_store._check_confidence(issue['issue_confidence'])):
                tmpstr_list.append("\n%s>> Issue: %s\n" % (
                    color.get(issue['issue_severity'], color['DEFAULT']),
                    issue['issue_text']
                ))
                tmpstr_list.append("   Severity: %s   Confidence: %s\n" % (
                    issue['issue_severity'].capitalize(),
                    issue['issue_confidence'].capitalize()
                ))
                tmpstr_list.append("   Location: %s:%s\n" % (
                    issue['fname'],
                    issue['lineno']
                ))
                tmpstr_list.append(color['DEFAULT'])

                tmpstr_list.append(
                    result_store._get_code(issue, True))

    result = ''.join(tmpstr_list)

    if result_store.out_file:
        with open(result_store.out_file, 'w') as fout:
            fout.write(result)
        result_store.logger.info("Text output written to file: %s",
                                 result_store.out_file)
    else:
        print(result)


def report_xml(result_store, file_list, scores, excluded_files):
    '''Prints/returns warnings in XML format (Xunit compatible)

    :param result_store: results of scan as BanditResultStore object
    :param files_list: Which files were inspected
    :param scores: The scores awarded to each file in the scope
    :param excluded_files: Which files were excluded from the scope
    :return: A collection containing the XML data
    '''

    import xml.etree.cElementTree as ET

    if result_store.out_file is None:
        result_store.out_file = 'bandit_results.xml'

    items = result_store.resstore.items()
    root = ET.Element('testsuite', name='bandit', tests=str(len(items)))
    for filename, issues in items:
        for issue in issues:
            test = issue['test']
            testcase = ET.SubElement(root, 'testcase',
                                     classname=filename, name=test)
            if (result_store._check_severity(issue['issue_severity']) and
                    result_store._check_confidence(issue['issue_confidence'])):
                text = 'Severity: %s Confidence: %s\n%s\nLocation %s:%s'
                text = text % (
                    issue['issue_severity'], issue['issue_confidence'],
                    issue['issue_text'], issue['fname'], issue['lineno'])
                ET.SubElement(testcase, 'error',
                              type=issue['issue_severity'],
                              message=issue['issue_text']).text = text

    tree = ET.ElementTree(root)
    tree.write(result_store.out_file, encoding='utf-8', xml_declaration=True)

    print("XML output written to file: %s" % result_store.out_file)
