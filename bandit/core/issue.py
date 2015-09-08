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

from bandit.core import constants
from bandit.core import utils

import linecache


class Issue(object):
    def __init__(self, severity, confidence=constants.CONFIDENCE_DEFAULT,
                 text="", ident=None):
        self.severity = severity
        self.confidence = confidence
        self.text = text
        self.ident = ident
        self.fname = ""
        self.test = ""
        self.lineno = -1
        self.linerange = []

    def __str__(self):
        return "Issue: '%s' from %s: Severity: %s Confidence: %s at %s:%i" % (
            self.text, (self.ident or self.test), self.severity,
            self.confidence, self.fname, self.lineno)

    def filter(self, confidence, severity):
        '''Used to filter on confidence and severity.

        This wil return false if either the confidence or severity of the issue
        are lower then the given threashold values.

        :param confidence: Confidence threashold
        :param confidence: Severity threashold
        '''
        rank = constants.RANKING
        return (rank.index(self.severity) >= rank.index(severity) and
                rank.index(self.confidence) >= rank.index(confidence))

    def get_code(self, max_lines=-1, tabbed=False):
        '''Gets lines of code from a file the generated this issue.

        :param max_lines: Max lines of context to return
        :param tabbed: Use tabbing in the output
        :return: strings of code
        '''
        lc = linecache
        file_len = sum(1 for line in open(self.fname))
        lines = utils.lines_with_context(self.lineno, self.linerange,
                                         max_lines, file_len)

        if not tabbed:
            return ''.join([lc.getline(self.fname, l) for l in lines])
        return ''.join(["%s\t%s" % (l, lc.getline(self.fname, l))
                        for l in lines])

    def as_dict(self, with_code=True):
        '''Convert the issue to a dict of values for outputting.'''
        out = {
            'filename': self.fname,
            'test_name': self.test,
            'issue_severity': self.severity,
            'issue_confidence': self.confidence,
            'issue_text': self.text,
            'line_number': self.lineno,
            'line_range': self.linerange,
            }

        if with_code:
            out['code'] = self.get_code()
        return out
