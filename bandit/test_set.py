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


import sys
from collections import OrderedDict
import glob
from inspect import getmembers, isfunction
import importlib



class BanditTestSet():

    tests = OrderedDict()

    def __init__(self, logger, test_config):
        self.logger = logger
        self.load_tests()

    def _get_decorators_list(self):
        '''
        Returns a list of decorator function names so that they can be ignored
        when discovering test function names.
        '''

        # we need to know the name of the decorators so that we can automatically
        # ignore them when discovering functions
        decorator_source_file = "bandit.test_selector"
        module = importlib.import_module(decorator_source_file)

        return_list = []
        decorators = [o for o in getmembers(module) if isfunction(o[1])]
        for d in decorators:
            return_list.append(d[0])
        return return_list

    def load_tests(self):
        '''
        Loads all tests from the plugins directory and puts them into the tests
        dictionary.
        '''

        # tests are a dictionary of functions, grouped by check type
        # where the key is the function name, and the value is the
        # function itself.
        #  eg.   tests[check_type][function_name] = function
        self.tests = dict()

        directory = 'plugins'  # TODO - parametize this at runtime

        decorators = self._get_decorators_list()
        # try to import each python file in the plugins directory
        for file in glob.glob1(directory, '*.py'):
            module_name = file.split('.')[0]

            # try to import the module by name
            try:
                module = importlib.import_module(directory + '.' + module_name)

            # if it fails, die
            except ImportError as e:
                self.logger.error("could not import test module '%s.%s'" %
                                  (directory, module_name))
                self.logger.error("\tdetail: '%s'" % (str(e)))
                sys.exit(2)

            # otherwise we want to obtain a list of all functions in the module
            # and add them to our dictionary of tests
            else:
                functions_list = [o for o in getmembers(module) if isfunction(o[1])]
                for cur_func in functions_list:

                    # for every function in the module, add it to the dictionary
                    # unless it's one of our decorators, in which case ignore it
                    function_name = cur_func[0]
                    if function_name not in decorators:
                        try:
                            function = getattr(module, function_name)
                        except AttributeError as e:
                            self.logger.error("could not locate test function "
                                    " '%s' in module '%s.%s" %
                                    (function_name, directory, module_name))
                            sys.exit(2)
                        else:
                            for check in function._checks:
                                # if this check type hasn't been encountered yet,
                                # initialize to empty dictionary
                                if check not in self.tests:
                                    self.tests[check] = {}
                                self.tests[check][function_name] = function

    def get_tests(self, checktype):
        '''
        Returns all tests that are of type checktype
        :param checktype: The type of test to filter on
        :return: A dictionary of tests which are of the specified type
        '''
        self.logger.debug('get_tests called with check type: %s' % checktype)
        scoped_tests = self.tests[checktype]
        self.logger.debug('get_tests returning scoped_tests : %s' %
                          scoped_tests)
        return scoped_tests
