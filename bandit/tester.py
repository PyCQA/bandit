#!/usr/bin/env python

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
