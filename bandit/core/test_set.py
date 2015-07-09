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


from collections import OrderedDict
import copy
import glob
import importlib
from inspect import getmembers
from inspect import isfunction
import os
import sys


class BanditTestSet():

    tests = OrderedDict()

    def __init__(self, logger, config, profile=None):
        self.logger = logger
        self.config = config
        filter_list = self._filter_list_from_config(profile=profile)
        self.load_tests(filter=filter_list)

    def _filter_list_from_config(self, profile=None):
        # will create an (include,exclude) list tuple from a specified name
        # config section

        # if a profile isn't set, there is nothing to do here
        if not profile:
            return_tuple = ([], [])
            return return_tuple

        # an empty include list means that all are included
        include_list = []
        # profile needs to be a dict, include needs to be an element in
        # profile, include needs to be a list, and 'all' is not in include
        if(isinstance(profile, dict) and 'include' in profile and
                isinstance(profile['include'], list) and
                'all' not in profile['include']):
            # there is a list of specific includes, add to the include list
            for inc in profile['include']:
                include_list.append(inc)

        # an empty exclude list means none are excluded, an exclude list with
        # 'all' means that all are excluded.  Specifically named excludes are
        # subtracted from the include list.
        exclude_list = []
        if(isinstance(profile, dict) and 'exclude' in profile and
                isinstance(profile['exclude'], list)):
            # it's a list, exclude specific tests
            for exc in profile['exclude']:
                exclude_list.append(exc)

        self.logger.debug(
            "_filter_list_from_config completed - include: %s, exclude %s",
            include_list, exclude_list
        )
        return_tuple = (include_list, exclude_list)
        return return_tuple

    def _filter_tests(self, filter):
        '''Filters the test set according to the filter tuple

        Filters the test set according to the filter tuple which contains
        include and exclude lists.
        :param filter: Include, exclude lists tuple
        :return: -
        '''
        include_list = filter[0]
        exclude_list = filter[1]

        # copy of tests dictionary for removing tests from
        temp_dict = copy.deepcopy(self.tests)

        # if the include list is empty, we don't have to do anything, if it
        # isn't, we need to remove all tests except the ones in the list
        if include_list:
            for check_type in self.tests:
                for test_name in self.tests[check_type]:
                    if test_name not in include_list:
                        del temp_dict[check_type][test_name]

        # remove the items specified in exclude list
        if exclude_list:
            for check_type in self.tests:
                for test_name in self.tests[check_type]:
                    if test_name in exclude_list:
                        del temp_dict[check_type][test_name]

        # copy tests back over from temp copy
        self.tests = copy.deepcopy(temp_dict)
        self.logger.debug('obtained filtered set of tests:')
        for k in self.tests:
            self.logger.debug('\t%s : %s', k, self.tests[k])

    def _get_decorators_list(self):
        '''Returns a list of decorator function names

        Returns a list of decorator function names so that they can be
        ignored when discovering test function names.
        '''

        # we need to know the name of the decorators so we can automatically
        # ignore them when discovering functions
        decorator_source_file = "bandit.core.test_properties"
        module = importlib.import_module(decorator_source_file)

        return_list = []
        decorators = [o for o in getmembers(module) if isfunction(o[1])]
        for d in decorators:
            return_list.append(d[0])
        self.logger.debug('_get_decorators_list returning: %s', return_list)
        return return_list

    def load_tests(self, filter=None):
        '''Loads all tests in the plugins directory into testsdictionary.'''

        # tests are a dictionary of functions, grouped by check type
        # where the key is the function name, and the value is the
        # function itself.
        #  eg.   tests[check_type][fn_name] = function
        self.tests = dict()

        directory = self.config.get_setting('plugins_dir')
        plugin_name_pattern = self.config.get_setting('plugin_name_pattern')

        decorators = self._get_decorators_list()
        # try to import each python file in the plugins directory
        sys.path.append(os.path.dirname(directory))
        for file in glob.glob1(directory, plugin_name_pattern):
            module_name = os.path.basename(file).split('.')[0]

            # try to import the module by name
            try:
                outer = os.path.basename(os.path.normpath(directory))
                self.logger.debug("importing plugin module: %s",
                                  outer + '.' + module_name)
                module = importlib.import_module(outer + '.' + module_name)

            # if it fails, die
            except ImportError as e:
                self.logger.error("could not import plugin module '%s.%s'",
                                  directory, module_name)
                self.logger.error("\tdetail: '%s'", str(e))
                sys.exit(2)

            # otherwise we want to obtain a list of all functions in the module
            # and add them to our dictionary of tests
            else:
                functions_list = [
                    o for o in getmembers(module) if isfunction(o[1])
                ]
                for cur_func in functions_list:
                    # for every function in the module, add to the dictionary
                    # unless it's one of our decorators, then ignore it
                    fn_name = cur_func[0]
                    if fn_name not in decorators:
                        try:
                            function = getattr(module, fn_name)
                        except AttributeError as e:
                            self.logger.error(
                                "could not locate test function '%s' in "
                                "module '%s.%s'",
                                fn_name, directory, module_name
                            )
                            sys.exit(2)
                        else:
                            if hasattr(function, '_checks'):
                                for check in function._checks:
                                    # if check type hasn't been encountered
                                    # yet, initialize to empty dictionary
                                    if check not in self.tests:
                                        self.tests[check] = {}
                                    # if there is a test name collision, bail
                                    if fn_name in self.tests[check]:
                                        self.logger.error(
                                            "Duplicate function definition "
                                            "%s in %s", fn_name, file
                                        )
                                        sys.exit(2)
                                    else:
                                        self.tests[check][fn_name] = function
                                        self.logger.debug(
                                            'added function %s targetting %s',
                                            fn_name, check
                                        )
        self._filter_tests(filter)

    def get_tests(self, checktype):
        '''Returns all tests that are of type checktype

        :param checktype: The type of test to filter on
        :return: A dictionary of tests which are of the specified type
        '''
        scoped_tests = {}
        self.logger.debug('get_tests called with check type: %s', checktype)
        if checktype in self.tests:
            scoped_tests = self.tests[checktype]
        self.logger.debug('get_tests returning scoped_tests : %s',
                          scoped_tests)
        return scoped_tests

    @property
    def has_tests(self):
        return bool(self.tests)
