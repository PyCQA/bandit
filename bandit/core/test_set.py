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


import importlib
import logging

from bandit.core import blacklisting
from bandit.core import extension_loader


logger = logging.getLogger(__name__)


class BanditTestSet():
    def __init__(self, config, profile=None):
        self.plugins = self._load_builtins()
        self.plugins.extend(extension_loader.MANAGER.plugins)

        if profile is not None:
            inc = profile.get('include') or None
            exc = profile.get('exclude') or None

            if inc is not None:
                self.plugins = [p for p in self.plugins if p.name in inc]

            if exc is not None:
                self.plugins = [p for p in self.plugins if p.name not in exc]

        self._load_tests(config, self.plugins)

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
                logger.debug('added function %s (%s) targetting %s',
                             plugin.name, plugin.plugin._test_id, check)

    def _load_builtins(self):
        '''loads up out builtin functions, so they can be filtered.'''
        class Wrapper:
            def __init__(self, name, plugin):
                self.name = name
                self.plugin = plugin

        # TODO(tkelsey): filter out blacklist items by profile

        # this dresses up the blacklist to look like a plugin, but the
        # 'checks' data comes from the blacklist information.
        setattr(blacklisting.blacklist, "_test_id", 'B001')
        setattr(blacklisting.blacklist, "_checks",
                extension_loader.MANAGER.blacklist.keys())
        return [Wrapper('blacklist', blacklisting.blacklist)]

    def get_tests(self, checktype):
        '''Returns all tests that are of type checktype

        :param checktype: The type of test to filter on
        :return: A list of tests which are of the specified type
        '''
        return self.tests.get(checktype) or []
