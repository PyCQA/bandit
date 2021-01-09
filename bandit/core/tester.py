# -*- coding:utf-8 -*-
#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0

import copy
import logging
import warnings

from bandit.core import constants
from bandit.core import context as b_context
from bandit.core import utils

warnings.formatwarning = utils.warnings_formatter
LOG = logging.getLogger(__name__)


class BanditTester(object):
    def __init__(self, testset, debug, nosec_lines):
        self.results = []
        self.testset = testset
        self.last_result = None
        self.debug = debug
        self.nosec_lines = nosec_lines

    def run_tests(self, raw_context, checktype):
        '''Runs all tests for a certain type of check, for example

        Runs all tests for a certain type of check, for example 'functions'
        store results in results.

        :param raw_context: Raw context dictionary
        :param checktype: The type of checks to run
        :param nosec_lines: Lines which should be skipped because of nosec
        :return: a score based on the number and type of test results
        '''

        scores = {
            'SEVERITY': [0] * len(constants.RANKING),
            'CONFIDENCE': [0] * len(constants.RANKING)
        }

        tests = self.testset.get_tests(checktype)
        for test in tests:
            name = test.__name__
            # execute test with the an instance of the context class
            temp_context = copy.copy(raw_context)
            context = b_context.Context(temp_context)
            try:
                if hasattr(test, '_config'):
                    result = test(context, test._config)
                else:
                    result = test(context)

                # if we have a result, record it and update scores
                if (result is not None and
                        result.lineno not in self.nosec_lines and
                        temp_context['lineno'] not in self.nosec_lines):

                    if isinstance(temp_context['filename'], bytes):
                        result.fname = temp_context['filename'].decode('utf-8')
                    else:
                        result.fname = temp_context['filename']

                    if result.lineno is None:
                        result.lineno = temp_context['lineno']
                    result.linerange = temp_context['linerange']
                    result.col_offset = temp_context['col_offset']
                    result.test = name
                    if result.test_id == "":
                        result.test_id = test._test_id

                    self.results.append(result)

                    LOG.debug("Issue identified by %s: %s", name, result)
                    sev = constants.RANKING.index(result.severity)
                    val = constants.RANKING_VALUES[result.severity]
                    scores['SEVERITY'][sev] += val
                    con = constants.RANKING.index(result.confidence)
                    val = constants.RANKING_VALUES[result.confidence]
                    scores['CONFIDENCE'][con] += val

            except Exception as e:
                self.report_error(name, context, e)
                if self.debug:
                    raise
        LOG.debug("Returning scores: %s", scores)
        return scores

    @staticmethod
    def report_error(test, context, error):
        what = "Bandit internal error running: "
        what += "%s " % test
        what += "on file %s at line %i: " % (
            context._context['filename'],
            context._context['lineno']
        )
        what += str(error)
        import traceback
        what += traceback.format_exc()
        LOG.error(what)
