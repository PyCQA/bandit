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

import collections
import json
import tempfile

import mock
import testtools

import bandit
from bandit.core import config
from bandit.core import constants
from bandit.core import issue
from bandit.core import manager
from bandit.core import metrics
from bandit.formatters import json as b_json


class JsonFormatterTests(testtools.TestCase):

    def setUp(self):
        super(JsonFormatterTests, self).setUp()
        conf = config.BanditConfig()
        self.manager = manager.BanditManager(conf, 'file')
        (tmp_fd, self.tmp_fname) = tempfile.mkstemp()
        self.context = {'filename': self.tmp_fname,
                        'lineno': 4,
                        'linerange': [4]}
        self.check_name = 'hardcoded_bind_all_interfaces'
        self.issue = issue.Issue(bandit.MEDIUM, bandit.MEDIUM,
                                 'Possible binding to all interfaces.')

        self.candidates = [issue.Issue(bandit.LOW, bandit.LOW, 'Candidate A',
                                       lineno=1),
                           issue.Issue(bandit.HIGH, bandit.HIGH, 'Candiate B',
                                       lineno=2)]

        self.manager.out_file = self.tmp_fname

        self.issue.fname = self.context['filename']
        self.issue.lineno = self.context['lineno']
        self.issue.linerange = self.context['linerange']
        self.issue.test = self.check_name

        self.manager.results.append(self.issue)
        self.manager.metrics = metrics.Metrics()

        # mock up the metrics
        for key in ['_totals', 'binding.py']:
            self.manager.metrics.data[key] = {'loc': 4, 'nosec': 2}
            for (criteria, default) in constants.CRITERIA:
                for rank in constants.RANKING:
                    self.manager.metrics.data[key]['{0}.{1}'.format(
                        criteria, rank
                    )] = 0

    @mock.patch('bandit.core.manager.BanditManager.get_issue_list')
    def test_report(self, get_issue_list):
        self.manager.files_list = ['binding.py']
        self.manager.scores = [{'SEVERITY': [0] * len(constants.RANKING),
                                'CONFIDENCE': [0] * len(constants.RANKING)}]

        get_issue_list.return_value = collections.OrderedDict(
            [(self.issue, self.candidates)])

        tmp_file = open(self.tmp_fname, 'w')
        b_json.report(self.manager, tmp_file, self.issue.severity,
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
            self.assertEqual({'CONFIDENCE': 0, 'SEVERITY': 0},
                             data['stats'][0]['score'])
            self.assertIn('candidates', data['results'][0])
