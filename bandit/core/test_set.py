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
from __future__ import print_function

import glob
import importlib
import logging
import os
import sys
import ast

from stevedore import extension

from bandit.core import blacklisting
from bandit.core import extension_loader

import ipdb
LOG = logging.getLogger(__name__)


class BanditTestSet(object):
    def __init__(self, config, profile=None):
        if not profile:
            profile = {}
        extman = extension_loader.MANAGER
        filtering = self._get_filter(config, profile)
        self.plugins = [p for p in extman.plugins
                        if p.plugin._test_id in filtering]
        self.plugins.extend(self._load_builtins(filtering, profile))
        self._load_dynamics_tests(profile)
        self._load_tests(config, self.plugins)

    @staticmethod
    def _get_filter(config, profile):
        extman = extension_loader.MANAGER

        inc = set(profile.get('include', []))
        exc = set(profile.get('exclude', []))

        all_blacklist_tests = set()
        for _node, tests in extman.blacklist.items():
            all_blacklist_tests.update(t['id'] for t in tests)

        # this block is purely for backwards compatibility, the rules are as
        # follows:
        # B001,B401 means B401
        # B401 means B401
        # B001 means all blacklist tests
        if 'B001' in inc:
            if not inc.intersection(all_blacklist_tests):
                inc.update(all_blacklist_tests)
            inc.discard('B001')
        if 'B001' in exc:
            if not exc.intersection(all_blacklist_tests):
                exc.update(all_blacklist_tests)
            exc.discard('B001')

        if inc:
            filtered = inc
        else:
            filtered = set(extman.plugins_by_id.keys())
            filtered.update(extman.builtin)
            filtered.update(all_blacklist_tests)
        return filtered - exc

    def _find_functions(self, filepath):
        f_ast = ast.parse(open(filepath).read())
        functions = []
        for value in f_ast.body:
            if isinstance(value, ast.FunctionDef):
                functions.append(value.name)
        return functions

    def _load_rule_from_file(self, filepath, exclude):
        if os.path.islink(filepath):
            LOG.info('Link not loaded {}'.format(filepath))
            return

        functions = self._find_functions(filepath)
        if not functions:
            LOG.debug('No functions finds')
            return

        LOG.debug('Loading {}'.format(filepath))
        module_name = os.path.basename(filepath)[:-3]
        rule_dir = os.path.dirname(filepath)
        base_path = os.getcwd()

        class Wrapper(object):
            def __init__(self, name, plugin):
                self.name = name
                self.plugin = plugin

        os.chdir(rule_dir)
        try:
            LOG.debug('Importing {}'.format(module_name))
            module = importlib.import_module(module_name)

            for funct in functions:
                dynamic_funct = getattr(module, funct)
                if hasattr(dynamic_funct, '_test_id'):
                    test_id = dynamic_funct._test_id
                    if test_id not in exclude:
                        self.plugins.append(Wrapper(test_id, dynamic_funct))
        finally:
            os.chdir(base_path)

    def _load_dynamics_tests(self, profile):
        exclude = profile.get('exclude', [])
        for rule_dir in profile.get('rules'):
            if os.path.isdir(rule_dir):
                rule_dir = "{}/{}".format(
                    os.path.dirname(rule_dir),
                    os.path.basename(rule_dir),
                )
                for filename in glob.glob('{}/*.py'.format(rule_dir)):
                    if os.path.isfile(filename):
                        self._load_rule_from_file(filename, exclude)
            elif rule_dir.endswith('.py'):
                self._load_rule_from_file(rule_dir, exclude)
            else:
                LOG.warning('Unsupported rule {}'.format(rule_dir))

    def _load_builtins(self, filtering, profile):
        '''loads up builtin functions, so they can be filtered.'''

        class Wrapper(object):
            def __init__(self, name, plugin):
                self.name = name
                self.plugin = plugin

        extman = extension_loader.MANAGER
        blacklist = profile.get('blacklist')
        if not blacklist:  # not overridden by legacy data
            blacklist = {}
            for node, tests in extman.blacklist.items():
                values = [t for t in tests if t['id'] in filtering]
                if values:
                    blacklist[node] = values

        if not blacklist:
            return []

        # this dresses up the blacklist to look like a plugin, but
        # the '_checks' data comes from the blacklist information.
        # the '_config' is the filtered blacklist data set.
        setattr(blacklisting.blacklist, "_test_id", 'B001')
        setattr(blacklisting.blacklist, "_checks", blacklist.keys())
        setattr(blacklisting.blacklist, "_config", blacklist)
        return [Wrapper('blacklist', blacklisting.blacklist)]

    def _load_tests(self, config, plugins):
        '''Builds a dict mapping tests to node types.'''
        self.tests = {}
        for plugin in plugins:
            if hasattr(plugin.plugin, '_takes_config'):
                # TODO(??): config could come from profile ...
                cfg = config.get_option(plugin.plugin._takes_config)
                if cfg is None:
                    genner = importlib.import_module(plugin.plugin.__module__)
                    cfg = genner.gen_config(plugin.plugin._takes_config)
                plugin.plugin._config = cfg
            for check in plugin.plugin._checks:
                self.tests.setdefault(check, []).append(plugin.plugin)
                LOG.debug('added function %s (%s) targeting %s',
                          plugin.name, plugin.plugin._test_id, check)

    def get_tests(self, checktype):
        '''Returns all tests that are of type checktype

        :param checktype: The type of test to filter on
        :return: A list of tests which are of the specified type
        '''
        return self.tests.get(checktype) or []
