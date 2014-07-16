#!/usr/bin/env python

from collections import OrderedDict

class BanditTestSet():

    tests = OrderedDict()

    #stubbed test
    def _test_import_name_match(self, context):
        info_on_import = ['pickle', 'subprocess', 'Crypto']
        for module in info_on_import:
            if context['module'] == module:
                return('INFO',
                       "Consider possible security implications"
                       " associated with '%s' module" % module)


    def __init__(self, logger):
        self.logger = logger
        self.load_tests()

    def load_tests(self):
        #each test should have a name, target node/s, and function...
        #for now, stub in some tests
        self.tests['import_name_match'] = {'targets': ['Import','ImportFrom'], 'function': self._test_import_name_match}

    def get_tests(self, nodetype):
        self.logger.debug('get_tests called with nodetype: %s' % nodetype)
        scoped_tests = {}
        for test in self.tests:
            if nodetype in self.tests[test]['targets']:
                scoped_tests[test] = self.tests[test]
        self.logger.debug('get_tests returning scoped_tests : %s' % scoped_tests)
        return scoped_tests

