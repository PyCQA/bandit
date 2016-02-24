# -*- coding:utf-8 -*-
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

import sys

import six
from stevedore import extension


class Manager(object):
    # These IDs are for bandit built in tests
    builtin = [
        'B001'  # Built in blacklist test
        ]

    def __init__(self, formatters_namespace='bandit.formatters',
                 plugins_namespace='bandit.plugins',
                 blacklists_namespace='bandit.blacklists'):
        # Cache the extension managers, loaded extensions, and extension names
        self.load_formatters(formatters_namespace)
        self.load_plugins(plugins_namespace)
        self.load_blacklists(blacklists_namespace)

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

    def load_blacklists(self, blacklist_namespace):
        self.blacklists_mgr = extension.ExtensionManager(
            namespace=blacklist_namespace,
            invoke_on_load=False,
            verify_requirements=False,
            )
        self.blacklist = {}
        blacklist = list(self.blacklists_mgr)
        for item in blacklist:
            for key, val in six.iteritems(item.plugin()):
                self.blacklist.setdefault(key, []).extend(val)

        self.blacklist_by_id = {}
        self.blacklist_by_name = {}
        for val in six.itervalues(self.blacklist):
            for b in val:
                self.blacklist_by_id[b['id']] = b
                self.blacklist_by_name[b['name']] = b

    def validate_profile(self, profile):
        '''Validate that everything in the configured profiles looks good.'''
        def _check(test):
            return (
                test not in self.plugins_by_id and
                test not in self.blacklist_by_id and
                test not in self.builtin)

        for inc in profile['include']:
            if _check(inc):
                raise ValueError('Unknown Test found in profile: %s' % inc)

        for exc in profile['exclude']:
            if _check(exc):
                raise ValueError('Unknown Test found in profile: %s' % exc)

        union = set(profile['include']) & set(profile['exclude'])
        if len(union) > 0:
            raise ValueError('None exclusive include/excule test sets: %s' %
                             union)


# Using entry-points and pkg_resources *can* be expensive. So let's load these
# once, store them on the object, and have a module global object for
# accessing them. After the first time this module is imported, it should save
# this attribute on the module and not have to reload the entry-points.
MANAGER = Manager()
