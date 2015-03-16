# -*- coding:utf-8 -*-
#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
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


import context as b_context
from constants import *  # noqa
import copy


class BanditTester():

    results = None

    def __init__(self, logger, config, results, testset, debug):
        self.logger = logger
        self.config = config
        self.results = results
        self.testset = testset
        self.last_result = None
        self.debug = debug

    def run_tests(self, raw_context, checktype):
        '''Runs all tests for a certain type of check, for example

        Runs all tests for a certain type of check, for example 'functions'
        store results in results.

        :param raw_context: Raw context dictionary
        :param checktype: The type of checks to run
        :return: a score based on the number and type of test results
        '''

        score = 0
        if not raw_context['lineno'] in raw_context['skip_lines']:
            tests = self.testset.get_tests(checktype)
            for name, test in tests.iteritems():
                # execute test with the an instance of the context class
                temp_context = copy.copy(raw_context)
                context = b_context.Context(temp_context)
                try:
                    if hasattr(test, '_takes_config'):
                        # TODO(??): Possibly allow override from profile
                        test_config = self.config.get_option(
                            test._takes_config)
                        result = test(context, test_config)
                    else:
                        result = test(context)
                    if result is not None:
                        self.results.add(temp_context, name, result)
                        score += SEVERITY_VALUES[result[0]]
                except Exception as e:
                    self.report_error(name, context, e)
                    if self.debug:
                        raise
        return score

    def report_error(self, test, context, error):
        what = "Bandit internal error running: "
        what += "%s " % test
        what += "on file %s at line %i: " % (
            context._context['filename'],
            context._context['lineno']
        )
        what += str(error)
        self.logger.error(what)
