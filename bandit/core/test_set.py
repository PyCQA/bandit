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
import importlib
import logging
import sys
import warnings

from bandit.core import blacklisting
from bandit.core import extension_loader
from bandit.core import utils


logger = logging.getLogger(__name__)


class BanditTestSet():

    tests = OrderedDict()

    def __init__(self, config, profile=None):
        self.config = config
        filter_list = self._filter_list_from_config(profile=profile)
        self.load_tests(filter=filter_list)

        # load blacklists
        for key in extension_loader.MANAGER.blacklist.keys():
            value = self.tests.setdefault(key, {})
            value["blacklist"] = blacklisting.blacklist

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

        logger.debug(
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

        extmgr = self._get_extension_manager()

        # if the include list is empty, we don't have to do anything, if it
        # isn't, we need to remove all tests except the ones in the list
        if include_list:
            for check_type in self.tests:
                for test_name in self.tests[check_type]:
                    if ((test_name not in include_list and
                         extmgr.get_plugin_id(test_name) not in include_list)):
                        del temp_dict[check_type][test_name]

        # remove the items specified in exclude list
        if exclude_list:
            for check_type in self.tests:
                for test_name in self.tests[check_type]:
                    if ((test_name in exclude_list or
                         extmgr.get_plugin_id(test_name) in exclude_list)):
                        del temp_dict[check_type][test_name]

        # copy tests back over from temp copy
        self.tests = copy.deepcopy(temp_dict)
        logger.debug('obtained filtered set of tests:')
        for k in self.tests:
            logger.debug('\t%s : %s', k, self.tests[k])

    def _get_extension_manager(self):
        from bandit.core import extension_loader
        return extension_loader.MANAGER

    def load_tests(self, filter=None):
        '''Loads all tests in the plugins directory into tests dictionary.'''
        self.tests = dict()

        extmgr = self._get_extension_manager()

        for plugin in extmgr.plugins:
            fn_name = plugin.name
            function = plugin.plugin
            if hasattr(function, '_takes_config'):
                test_config = self.config.get_option(function._takes_config)
                if test_config is None:
                    genner = importlib.import_module(function.__module__)
                    if hasattr(genner, 'gen_config'):
                        test_config = genner.gen_config(function._takes_config)
                if test_config is None:
                    warnings.warn(
                        '"{0}" has been skipped due to missing config '
                        '"{1}".'.format(function.__name__,
                                        function._takes_config))
                    continue
                else:
                    setattr(function, "_config", test_config)

            if hasattr(function, '_checks'):
                for check in function._checks:
                    # if check type hasn't been encountered
                    # yet, initialize to empty dictionary
                    if check not in self.tests:
                        self.tests[check] = {}
                    # if there is a test name collision, bail
                    if fn_name in self.tests[check]:
                        path1 = (utils.get_path_for_function(function) or
                                 '(unknown)')
                        path2 = utils.get_path_for_function(
                            self.tests[check][fn_name]) or '(unknown)'
                        logger.error(
                            "Duplicate function definition "
                            "%s in %s and %s", fn_name, path1, path2
                            )
                        sys.exit(2)
                    else:
                        self.tests[check][fn_name] = function
                        logger.debug(
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
        logger.debug('get_tests called with check type: %s', checktype)
        if checktype in self.tests:
            scoped_tests = self.tests[checktype]
        logger.debug('get_tests returning scoped_tests : %s', scoped_tests)
        return scoped_tests

    @property
    def has_tests(self):
        result = False
        for check_type in self.tests:
            result = result or self.tests[check_type]
        return result
