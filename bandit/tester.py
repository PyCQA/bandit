# -*- coding:utf-8 -*-
#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


import utils
import bandit.context as b_context

class BanditTester():

    results = None

    def __init__(self, logger, results, testset):
        self.logger = logger
        self.results = results
        self.testset = testset
        self.last_result = None

    def run_tests(self, raw_context, checktype):
        '''
        Runs all tests for a certain type of check, for example 'functions',
        store results in results.
        :param raw_context: Raw context dictionary
        :param checktype: The type of checks to run
        :return: none
        '''
        tests = self.testset.get_tests(checktype)
        for test in tests:
            # execute test with the an instance of the context class
            context = b_context.Context(raw_context)
            result = tests[test](context)
            if result is not None:
                self.results.add(raw_context, result)
