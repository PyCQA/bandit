# -*- coding:utf-8 -*-
#
# Copyright 2015 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import division
from __future__ import unicode_literals

import linecache

from bandit.core import constants


class Issue(object):
    def __init__(self, severity, confidence=constants.CONFIDENCE_DEFAULT,
                 text="", ident=None, lineno=None, test_id="", col_offset=0):
        self.severity = severity
        self.confidence = confidence
        if isinstance(text, bytes):
            text = text.decode('utf-8')
        self.text = text
        self.ident = ident
        self.fname = ""
        self.test = ""
        self.test_id = test_id
        self.lineno = lineno
        self.col_offset = col_offset
        self.linerange = []

    def __str__(self):
        return ("Issue: '%s' from %s:%s: Severity: %s Confidence: "
                "%s at %s:%i") % (self.text, self.test_id,
                                  (self.ident or self.test), self.severity,
                                  self.confidence, self.fname, self.lineno)

    def __eq__(self, other):
        # if the issue text, severity, confidence, and filename match, it's
        # the same issue from our perspective
        match_types = ['text', 'severity', 'confidence', 'fname', 'test',
                       'test_id']
        return all(getattr(self, field) == getattr(other, field)
                   for field in match_types)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return id(self)

    def filter(self, severity, confidence):
        '''Utility to filter on confidence and severity

        This function determines whether an issue should be included by
        comparing the severity and confidence rating of the issue to minimum
        thresholds specified in 'severity' and 'confidence' respectively.

        Formatters should call manager.filter_results() directly.

        This will return false if either the confidence or severity of the
        issue are lower than the given threshold values.

        :param severity: Severity threshold
        :param confidence: Confidence threshold
        :return: True/False depending on whether issue meets threshold

        '''
        rank = constants.RANKING
        return (rank.index(self.severity) >= rank.index(severity) and
                rank.index(self.confidence) >= rank.index(confidence))

    def get_code(self, max_lines=3, tabbed=False):
        '''Gets lines of code from a file the generated this issue.

        :param max_lines: Max lines of context to return
        :param tabbed: Use tabbing in the output
        :return: strings of code
        '''
        lines = []
        max_lines = max(max_lines, 1)
        lmin = max(1, self.lineno - max_lines // 2)
        lmax = lmin + len(self.linerange) + max_lines - 1

        tmplt = "%i\t%s" if tabbed else "%i %s"
        for line in range(lmin, lmax):
            text = linecache.getline(self.fname, line)

            if isinstance(text, bytes):
                text = text.decode('utf-8')

            if not len(text):
                break
            lines.append(tmplt % (line, text))
        return ''.join(lines)

    def as_dict(self, with_code=True):
        '''Convert the issue to a dict of values for outputting.'''
        out = {
            'filename': self.fname,
            'test_name': self.test,
            'test_id': self.test_id,
            'issue_severity': self.severity,
            'issue_confidence': self.confidence,
            'issue_text': self.text.encode('utf-8').decode('utf-8'),
            'line_number': self.lineno,
            'line_range': self.linerange,
            'col_offset': self.col_offset
            }

        if with_code:
            out['code'] = self.get_code()
        return out

    def from_dict(self, data, with_code=True):
        self.code = data["code"]
        self.fname = data["filename"]
        self.severity = data["issue_severity"]
        self.confidence = data["issue_confidence"]
        self.text = data["issue_text"]
        self.test = data["test_name"]
        self.test_id = data["test_id"]
        self.lineno = data["line_number"]
        self.linerange = data["line_range"]
        self.col_offset = data.get("col_offset", 0)


def issue_from_dict(data):
    i = Issue(severity=data["issue_severity"])
    i.from_dict(data)
    return i
