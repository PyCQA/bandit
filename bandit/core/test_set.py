# -*- coding:utf-8 -*-
#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0


import importlib
import logging


from bandit.core import banlisting
from bandit.core import extension_loader


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
        self._load_tests(config, self.plugins)

    @staticmethod
    def _get_filter(config, profile):
        extman = extension_loader.MANAGER

        inc = set(profile.get('include', []))
        exc = set(profile.get('exclude', []))

        all_banlist_tests = set()
        for _, tests in extman.banlist.items():
            all_banlist_tests.update(t['id'] for t in tests)

        # this block is purely for backwards compatibility, the rules are as
        # follows:
        # B001,B401 means B401
        # B401 means B401
        # B001 means all banlist tests
        if 'B001' in inc:
            if not inc.intersection(all_banlist_tests):
                inc.update(all_banlist_tests)
            inc.discard('B001')
        if 'B001' in exc:
            if not exc.intersection(all_banlist_tests):
                exc.update(all_banlist_tests)
            exc.discard('B001')

        if inc:
            filtered = inc
        else:
            filtered = set(extman.plugins_by_id.keys())
            filtered.update(extman.builtin)
            filtered.update(all_banlist_tests)
        return filtered - exc

    def _load_builtins(self, filtering, profile):
        '''loads up builtin functions, so they can be filtered.'''

        class Wrapper(object):
            def __init__(self, name, plugin):
                self.name = name
                self.plugin = plugin

        extman = extension_loader.MANAGER
        banlist = profile.get('banlist')
        if not banlist:  # not overridden by legacy data
            banlist = {}
            for node, tests in extman.banlist.items():
                values = [t for t in tests if t['id'] in filtering]
                if values:
                    banlist[node] = values

        if not banlist:
            return []

        # this dresses up the banlist to look like a plugin, but
        # the '_checks' data comes from the banlist information.
        # the '_config' is the filtered banlist data set.
        banlisting.banlist._test_id = "B001"
        banlisting.banlist._checks = banlist.keys()
        banlisting.banlist._config = banlist

        return [Wrapper('banlist', banlisting.banlist)]

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
