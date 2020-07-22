# -*- coding:utf-8 -*-
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import print_function

import sys
import warnings

import six
from stevedore import extension

from bandit.core import utils


class Manager(object):
    # These IDs are for bandit built in tests
    builtin = [
        'B001'  # Built in banlist test
        ]

    def __init__(self, formatters_namespace='bandit.formatters',
                 plugins_namespace='bandit.plugins',
                 banlists_namespace='bandit.banlists',
                 load_legacy_blacklists=True):
        # Cache the extension managers, loaded extensions, and extension names
        self.load_formatters(formatters_namespace)
        self.load_plugins(plugins_namespace)
        self.load_banlists(banlists_namespace, load_legacy_blacklists)

    def load_formatters(self, formatters_namespace):
        self.formatters_mgr = extension.ExtensionManager(
            namespace=formatters_namespace,
            invoke_on_load=False,
            verify_requirements=False,
            )
        self.formatters = list(self.formatters_mgr)
        self.formatter_names = self.formatters_mgr.names()

    def load_plugins(self, plugins_namespace):
        self.plugins_mgr = extension.ExtensionManager(
            namespace=plugins_namespace,
            invoke_on_load=False,
            verify_requirements=False,
            )

        def test_has_id(plugin):
            if not hasattr(plugin.plugin, "_test_id"):
                # logger not setup yet, so using print
                print("WARNING: Test '%s' has no ID, skipping." % plugin.name,
                      file=sys.stderr)
                return False
            return True

        self.plugins = list(filter(test_has_id, list(self.plugins_mgr)))
        self.plugin_names = [plugin.name for plugin in self.plugins]
        self.plugins_by_id = {p.plugin._test_id: p for p in self.plugins}
        self.plugins_by_name = {p.name: p for p in self.plugins}

    def get_plugin_id(self, plugin_name):
        if plugin_name in self.plugins_by_name:
            return self.plugins_by_name[plugin_name].plugin._test_id
        return None

    def load_banlists(self, banlist_namespace, load_legacy_blacklists=True):
        self.banlists_mgr = extension.ExtensionManager(
            namespace=banlist_namespace,
            invoke_on_load=False,
            verify_requirements=False,
            )
        self.banlist = {}
        banlist = list(self.banlists_mgr)

        if load_legacy_blacklists:
            self.legacy_banlists_mgr = extension.ExtensionManager(
                namespace='bandit.blacklists',
                invoke_on_load=False,
                verify_requirements=False,
            )
            legacy_banlist = list(self.legacy_banlists_mgr)
            if len(legacy_banlist) > 0:
                warnings.warn(
                    "bandit.blacklists will be deprecated in future versions, use bandit.banlists instead.",
                    PendingDeprecationWarning)
            banlist = banlist + legacy_banlist

        for item in banlist:
            for key, val in item.plugin().items():
                utils.check_ast_node(key)
                self.banlist.setdefault(key, []).extend(val)

        self.banlist_by_id = {}
        self.banlist_by_name = {}
        for val in six.itervalues(self.banlist):
            for b in val:
                self.banlist_by_id[b['id']] = b
                self.banlist_by_name[b['name']] = b

    def validate_profile(self, profile):
        '''Validate that everything in the configured profiles looks good.'''
        for inc in profile['include']:
            if not self.check_id(inc):
                raise ValueError('Unknown test found in profile: %s' % inc)

        for exc in profile['exclude']:
            if not self.check_id(exc):
                raise ValueError('Unknown test found in profile: %s' % exc)

        union = set(profile['include']) & set(profile['exclude'])
        if len(union) > 0:
            raise ValueError('Non-exclusive include/exclude test sets: %s' %
                             union)

    def check_id(self, test):
        return (
            test in self.plugins_by_id or
            test in self.banlist_by_id or
            test in self.builtin)


# Using entry-points and pkg_resources *can* be expensive. So let's load these
# once, store them on the object, and have a module global object for
# accessing them. After the first time this module is imported, it should save
# this attribute on the module and not have to reload the entry-points.
MANAGER = Manager()
