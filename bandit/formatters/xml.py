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
Description
-----------
This formatter outputs the issues as XML.

Sample Output
-------------
.. code-block:: xml

    <?xml version='1.0' encoding='utf-8'?>
    <testsuite name="bandit" tests="1"><testcase
    classname="examples/yaml_load.py" name="blacklist_calls"><error
    message="Use of unsafe yaml load. Allows instantiation of arbitrary
    objects. Consider yaml.safe_load().&#10;" type="MEDIUM">Severity: MEDIUM
    Confidence: HIGH Use of unsafe yaml load. Allows instantiation of arbitrary
    objects. Consider yaml.safe_load().

    Location examples/yaml_load.py:5</error></testcase></testsuite>

.. versionadded:: 0.12.0

"""

from __future__ import absolute_import
import logging
import sys
from xml.etree import cElementTree as ET

logger = logging.getLogger(__name__)


def report(manager, filename, sev_level, conf_level, lines=-1):
    '''Prints issues in XML formt

    :param manager: the bandit manager object
    :param filename: The output file name, or None for stdout
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param lines: Number of lines to report, -1 for all
    '''

    issues = manager.get_issue_list(sev_level=sev_level, conf_level=conf_level)
    root = ET.Element('testsuite', name='bandit', tests=str(len(issues)))

    for issue in issues:
        test = issue.test
        testcase = ET.SubElement(root, 'testcase',
                                 classname=issue.fname, name=test)

        text = 'Severity: %s Confidence: %s\n%s\nLocation %s:%s'
        text = text % (
            issue.severity, issue.confidence,
            issue.text, issue.fname, issue.lineno)
        ET.SubElement(testcase, 'error',
                      type=issue.severity,
                      message=issue.text).text = text

    tree = ET.ElementTree(root)

    outfile = sys.stdout
    if filename is not None:
        outfile = open(filename, "wb")

    tree.write(outfile, encoding='utf-8', xml_declaration=True)

    if filename is not None:
        logger.info("XML output written to file: %s" % filename)
