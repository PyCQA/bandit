# -*- coding:utf-8 -*-
#
# Copyright 2015 Hewlett-Packard Development Company, L.P.
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

from collections import Counter

from bandit.core import constants


class Metrics(object):
    """Bandit metric gathering.

    This class is a singleton used to gather and process metrics collected when
    processing a code base with bandit. Metric collection is stateful, that
    is, an active metric block will be set when requested and all subsequent
    operations will effect that metric block until it is replaced by a setting
    a new one.
    """

    def __init__(self):
        self.data = dict()
        self.data['_totals'] = {'loc': 0, 'nosec': 0}

        # initialize 0 totals for criteria and rank; this will be reset later
        for rank in constants.RANKING:
            for criteria in constants.CRITERIA:
                self.data['_totals']['{0}.{1}'.format(criteria[0], rank)] = 0

    def begin(self, fname):
        """Begin a new metric block.

        This starts a new metric collection name "fname" and makes is active.

        :param fname: the metrics unique name, normally the file name.
        """
        self.data[fname] = {'loc': 0, 'nosec': 0}
        self.current = self.data[fname]

    def note_nosec(self, num=1):
        """Note a "nosec" commnet.

        Increment the currently active metrics nosec count.

        :param num: number of nosecs seen, defaults to 1
        """
        self.current['nosec'] += num

    def count_locs(self, lines):
        """Count lines of code.

        We count lines that are not empty and are not comments. The result is
        added to our currently active metrics loc count (normally this is 0).

        :param lines: lines in the file to process
        """
        def proc(line):
            tmp = line.strip()
            return tmp and not tmp.startswith(b'#')

        self.current['loc'] += len(list(filter(proc, lines)))

    def count_issues(self, scores):
        self.current.update(self._get_issue_counts(scores))

    def aggregate(self):
        """Do final aggregation of metrics."""
        c = Counter()
        for fname in self.data:
            c.update(self.data[fname])
        self.data['_totals'] = dict(c)

    def _get_issue_counts(self, scores):
        """Get issue counts aggregated by confidence/severity rankings.

        :param scores: list of scores to aggregate / count
        :return: aggregated total (count) of issues identified
        """
        issue_counts = {}
        for score in scores:
            for (criteria, default) in constants.CRITERIA:
                for i, rank in enumerate(constants.RANKING):
                    label = '{0}.{1}'.format(criteria, rank)
                    if label not in issue_counts:
                        issue_counts[label] = 0
                        count = (
                            score[criteria][i] /
                            constants.RANKING_VALUES[rank]
                        )
                        issue_counts[label] += count
        return issue_counts
