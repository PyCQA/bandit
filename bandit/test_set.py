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


import sys
from collections import OrderedDict
import ConfigParser


class BanditTestSet():

    tests = OrderedDict()

    def __init__(self, logger, test_config):
        self.logger = logger
        self.load_tests(test_config)

    def load_tests(self, test_config):
        config = ConfigParser.RawConfigParser()
        config.read(test_config)
        self.tests = OrderedDict()
        directory = 'plugins'  # TODO - parametize this at runtime
        for target in config.sections():
            for (test_name_func, test_name_mod) in config.items(target):
                if test_name_func not in self.tests:
                    self.tests[test_name_func] = {'targets': []}
                    test_mod = None
                    try:
                        test_mod = __import__(
                            '%s.%s' % (directory, test_name_mod),
                            fromlist=[directory, ]
                        )
                    except ImportError as e:
                        self.logger.error(
                            "could not import test module '%s.%s'" %
                            (directory, test_name_mod)
                        )
                        self.logger.error("\tdetail: '%s'" % (str(e)))
                        del(self.tests[test_name_func])
                        sys.exit(2)
                    else:
                        try:
                            test_func = getattr(test_mod, test_name_func)
                        except AttributeError as e:
                            self.logger.error("could not locate test function"
                                              " '%s' in module '%s.%s'" %
                                              (test_name_func, directory,
                                               test_name_mod))
                            del(self.tests[test_name_func])
                            sys.exit(2)
                        else:
                            self.tests[test_name_func]['function'] = test_func
                self.tests[test_name_func]['targets'].append(target)

    def get_tests(self, nodetype):
        self.logger.debug('get_tests called with nodetype: %s' % nodetype)
        scoped_tests = {}
        for test in self.tests:
            if nodetype in self.tests[test]['targets']:
                scoped_tests[test] = self.tests[test]
        self.logger.debug('get_tests returning scoped_tests : %s' %
                          scoped_tests)
        return scoped_tests
