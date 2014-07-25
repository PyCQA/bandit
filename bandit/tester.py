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


class BanditTester():

    results = None

    def __init__(self, logger, results, testset):
        self.logger = logger
        self.results = results
        self.testset = testset
        self.last_result = None

    def run_tests(self, context, nodetype):
        tests = self.testset.get_tests(nodetype)
        for test in tests:
            # execute test with the relevant details to the current node
            result = tests[test]['function'](context)
            if result is not None:
                self.results.add(context, result)
