#!/usr/bin/env python

from collections import OrderedDict

class BanditTestSet():

    tests = OrderedDict()

    #stubbed test
    def _test_import_name_match(node, name):
        self.logger.debug('_test_import_name_match executed with name : %s' % name)
        warn_on_import = ['pickle', 'subprocess', 'Crypto']
        for mod in warn_on_import:
            if name.startswith(mod):
                return('INFO', "Consider possible security implications associated with '%s' module" % mod)


    def __init__(self, logger):
        self.logger = logger
        self.load_tests()

    def load_tests(self):
        #each test should have a name, target node/s, and function...
        #for now, stub in some tests
        self.tests['import_name_match'] = {'targets': ['', ''], 'function': self._test_import_name_match}

    def get_tests(self):
        return tests

