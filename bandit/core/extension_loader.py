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

import importlib
import logging
import os
import sys

import six
from stevedore import extension

from bandit.core import utils

LOG = logging.getLogger(__name__)


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

        self.dynamic = []
        self.dynamic_by_id = {}
        self.dynamic_by_name = {}

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
            for key, val in item.plugin().items():
                utils.check_ast_node(key)
                self.blacklist.setdefault(key, []).extend(val)

        self.blacklist_by_id = {}
        self.blacklist_by_name = {}
        for val in six.itervalues(self.blacklist):
            for b in val:
                self.blacklist_by_id[b['id']] = b
                self.blacklist_by_name[b['name']] = b

    def load_dynamic(self, profile):
        self.dynamic = []
        self.dynamic_by_id = {}
        self.dynamic_by_name = {}

        class Wrapper(object):
            def __init__(self, _test_id, _name, plugin):
                self._test_id = _test_id
                self.name = _name
                self.plugin = plugin

        dir_list = profile.get('rules', [])
        if not dir_list:
            return

        if sys.path[0] != '':
            sys.path.insert(0, '')

        for file_path in utils.find_files(dir_list):
            if os.path.islink(file_path):
                file_path = os.path.realpath(file_path)

            loaders = utils.find_loaders(file_path)
            if not loaders:
                LOG.debug('No functions nor class finds')
                continue

            LOG.debug('Loading %s', file_path)
            module_name = os.path.basename(file_path)[:-3]
            rule_dir = os.path.dirname(file_path)
            base_path = os.getcwd()

            os.chdir(rule_dir)

            try:
                module = importlib.import_module(module_name)

                for loader in loaders:
                    dynamic_loader = getattr(module, loader)
                    if callable(dynamic_loader) and \
                       hasattr(dynamic_loader, '_test_id'):

                        test_id = dynamic_loader._test_id
                        name = "{}_{}".format(module_name, loader)
                        wrapper = Wrapper(test_id, name, dynamic_loader)
                        self.dynamic.append(wrapper)
                        self.dynamic_by_id[test_id] = wrapper
                        self.dynamic_by_name[name] = wrapper
            except ImportError:
                LOG.exception('Cannot import %s on %s',
                              module_name,
                              os.getcwd())
            finally:
                os.chdir(base_path)

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
        return (test in self.plugins_by_id or
                test in self.blacklist_by_id or
                test in self.dynamic_by_id or
                test in self.builtin)


# Using entry-points and pkg_resources *can* be expensive. So let's load these
# once, store them on the object, and have a module global object for
# accessing them. After the first time this module is imported, it should save
# this attribute on the module and not have to reload the entry-points.
MANAGER = Manager()
