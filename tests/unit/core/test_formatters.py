# Copyright (c) 2015 VMware, Inc.
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

from collections import defaultdict
import csv
import json
import os
import tempfile
from xml.etree import cElementTree as ET

import six
import testtools

import bandit
from bandit.core import constants
from bandit.core import config
from bandit.core import manager
from bandit.core import formatters
from bandit.core import issue


class FormattersTests(testtools.TestCase):

    def setUp(self):
        super(FormattersTests, self).setUp()
        cfg_file = os.path.join(os.getcwd(), 'bandit/config/bandit.yaml')
        conf = config.BanditConfig(cfg_file)
        self.manager = manager.BanditManager(conf, 'file')
        (tmp_fd, self.tmp_fname) = tempfile.mkstemp()
        self.context = {'filename': self.tmp_fname,
                        'lineno': 4,
                        'linerange': [4]}
        self.check_name = 'hardcoded_bind_all_interfaces'
        self.issue = issue.Issue(bandit.MEDIUM, bandit.MEDIUM,
                      'Possible binding to all interfaces.')
        self.manager.out_file = self.tmp_fname

        self.issue.fname = self.context['filename']
        self.issue.lineno = self.context['lineno']
        self.issue.linerange = self.context['linerange']
        self.issue.test = self.check_name

        self.manager.results.append(self.issue)

    def test_report_csv(self):
        formatters.report_csv(self.manager, self.tmp_fname,
                              self.issue.severity, self.issue.confidence)

        with open(self.tmp_fname) as f:
            reader = csv.DictReader(f)
            data = six.next(reader)
            self.assertEqual(self.tmp_fname, data['filename'])
            self.assertEqual(self.issue.severity, data['issue_severity'])
            self.assertEqual(self.issue.confidence, data['issue_confidence'])
            self.assertEqual(self.issue.text, data['issue_text'])
            self.assertEqual(six.text_type(self.context['lineno']),
                             data['line_number'])
            self.assertEqual(six.text_type(self.context['linerange']),
                             data['line_range'])
            self.assertEqual(self.check_name, data['test_name'])

    def test_report_json(self):
        self.manager.files_list = ['binding.py']
        self.manager.scores = [{'SEVERITY': [0] * len(constants.RANKING),
                                'CONFIDENCE': [0] * len(constants.RANKING)}]

        formatters.report_json(self.manager, self.tmp_fname,
                               self.issue.severity, self.issue.confidence)

        with open(self.tmp_fname) as f:
            data = json.loads(f.read())
            self.assertIsNotNone(data['generated_at'])
            self.assertEqual(self.tmp_fname, data['results'][0]['filename'])
            self.assertEqual(self.issue.severity,
                             data['results'][0]['issue_severity'])
            self.assertEqual(self.issue.confidence,
                             data['results'][0]['issue_confidence'])
            self.assertEqual(self.issue.text, data['results'][0]['issue_text'])
            self.assertEqual(self.context['lineno'],
                             data['results'][0]['line_number'])
            self.assertEqual(self.context['linerange'],
                             data['results'][0]['line_range'])
            self.assertEqual(self.check_name, data['results'][0]['test_name'])
            self.assertEqual('binding.py', data['stats'][0]['filename'])
            self.assertEqual(0, data['stats'][0]['score'])

    def test_report_text(self):
        self.manager.verbose = True
        file_list = ['binding.py']
        scores = [{'SEVERITY': [0] * len(constants.RANKING),
                   'CONFIDENCE': [0] * len(constants.RANKING)}]
        exc_files = ['test_binding.py']

        formatters.report_text(self.manager, self.tmp_fname,
                               self.issue.severity, self.issue.confidence)

        with open(self.tmp_fname) as f:
            data = f.read()
            expected = '>> Issue: %s' % self.issue.text
            self.assertIn(expected, data)
            expected = '   Severity: %s   Confidence: %s' % (
                self.issue.severity.capitalize(),
                self.issue.confidence.capitalize())
            self.assertIn(expected, data)
            expected = '   Location: %s:%d' % (self.tmp_fname,
                                               self.context['lineno'])
            self.assertIn(expected, data)

    def _xml_to_dict(self, t):
        d = {t.tag: {} if t.attrib else None}
        children = list(t)
        if children:
            dd = defaultdict(list)
            for dc in map(self._xml_to_dict, children):
                for k, v in six.iteritems(dc):
                    dd[k].append(v)
            d = {t.tag: {k:v[0] if len(v) == 1 else v for k, v in six.iteritems(dd)}}
        if t.attrib:
            d[t.tag].update(('@' + k, v) for k, v in six.iteritems(t.attrib))
        if t.text:
            text = t.text.strip()
            if children or t.attrib:
                if text:
                  d[t.tag]['#text'] = text
            else:
                d[t.tag] = text
        return d

    def test_report_xml(self):
        formatters.report_xml(self.manager, self.tmp_fname,
                             self.issue.severity, self.issue.confidence)

        with open(self.tmp_fname) as f:
            data = self._xml_to_dict(ET.XML(f.read()))
            self.assertEqual(self.tmp_fname,
                data['testsuite']['testcase']['@classname'])
            self.assertEqual(self.issue.text,
                data['testsuite']['testcase']['error']['@message'])
            self.assertEqual(self.check_name,
                data['testsuite']['testcase']['@name'])
