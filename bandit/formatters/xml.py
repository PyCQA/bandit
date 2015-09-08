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
from xml.etree import cElementTree as ET


def report(manager, filename, sev_level, conf_level, lines=-1,
           out_format='xml'):
    '''Prints issues in XML formt

    :param manager: the bandit manager object
    :param filename: The output file name, or None for stdout
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param lines: Number of lines to report, -1 for all
    :param out_format: The ouput format name
    '''

    if filename is None:
        filename = 'bandit_results.xml'

    issues = manager.get_issue_list()
    root = ET.Element('testsuite', name='bandit', tests=str(len(issues)))

    for issue in issues:
        test = issue.test
        testcase = ET.SubElement(root, 'testcase',
                                 classname=issue.fname, name=test)
        if issue.filter(sev_level, conf_level):
            text = 'Severity: %s Confidence: %s\n%s\nLocation %s:%s'
            text = text % (
                issue.severity, issue.confidence,
                issue.text, issue.fname, issue.lineno)
            ET.SubElement(testcase, 'error',
                          type=issue.severity,
                          message=issue.text).text = text

    tree = ET.ElementTree(root)
    tree.write(filename, encoding='utf-8', xml_declaration=True)

    print("XML output written to file: %s" % filename)
