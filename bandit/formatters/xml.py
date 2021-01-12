# -*- coding:utf-8 -*-
#
# SPDX-License-Identifier: Apache-2.0

r"""
=============
XML Formatter
=============

This formatter outputs the issues as XML.

:Example:

.. code-block:: xml

    <?xml version='1.0' encoding='utf-8'?>
    <testsuite name="bandit" tests="1"><testcase
    classname="examples/yaml_load.py" name="blacklist_calls"><error
    message="Use of unsafe yaml load. Allows instantiation of arbitrary
    objects. Consider yaml.safe_load().&#10;" type="MEDIUM"
    more_info="https://bandit.readthedocs.io/en/latest/">Test ID: B301
    Severity: MEDIUM Confidence: HIGH Use of unsafe yaml load. Allows
    instantiation of arbitrary objects. Consider yaml.safe_load().

    Location examples/yaml_load.py:5</error></testcase></testsuite>

.. versionadded:: 0.12.0

"""
# This future import is necessary here due to the xml import below on Python
# 2.7
from __future__ import absolute_import

import logging
import sys
from xml.etree import cElementTree as ET

from bandit.core import docs_utils

LOG = logging.getLogger(__name__)


def report(manager, fileobj, sev_level, conf_level, lines=-1):
    '''Prints issues in XML format

    :param manager: the bandit manager object
    :param fileobj: The output file object, which may be sys.stdout
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

        text = 'Test ID: %s Severity: %s Confidence: %s\n%s\nLocation %s:%s'
        text = text % (issue.test_id, issue.severity, issue.confidence,
                       issue.text, issue.fname, issue.lineno)
        ET.SubElement(testcase, 'error',
                      more_info=docs_utils.get_url(issue.test_id),
                      type=issue.severity,
                      message=issue.text).text = text

    tree = ET.ElementTree(root)

    if fileobj.name == sys.stdout.name:
        fileobj = sys.stdout.buffer
    elif fileobj.mode == 'w':
        fileobj.close()
        fileobj = open(fileobj.name, "wb")

    with fileobj:
        tree.write(fileobj, encoding='utf-8', xml_declaration=True)

    if fileobj.name != sys.stdout.name:
        LOG.info("XML output written to file: %s", fileobj.name)
