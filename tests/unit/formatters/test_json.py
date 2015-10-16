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

import json
import os
import tempfile

import testtools

import bandit
from bandit.core import constants
from bandit.core import config
from bandit.core import manager
from bandit.core import metrics
from bandit.core import issue
from bandit.formatters import json as b_json

class JsonFormatterTests(testtools.TestCase):

    def setUp(self):
        super(JsonFormatterTests, self).setUp()
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
        metrics.metrics = metrics.Metrics()

    def test_report(self):
        self.manager.files_list = ['binding.py']
        self.manager.scores = [{'SEVERITY': [0] * len(constants.RANKING),
                                'CONFIDENCE': [0] * len(constants.RANKING)}]

        b_json.report(self.manager, self.tmp_fname, self.issue.severity,
                      self.issue.confidence)

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
