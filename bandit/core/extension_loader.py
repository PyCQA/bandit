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

from stevedore import extension


class Manager(object):
    def __init__(self, formatters_namespace='bandit.formatters',
                 plugins_namespace='bandit.plugins'):
        # Cache the extension managers, loaded extensions, and extension names
        self.load_formatters(formatters_namespace)
        self.formatters = list(self.formatters_mgr)
        self.formatter_names = self.formatters_mgr.names()

        self.load_plugins(plugins_namespace)
        self.plugins = list(self.plugins_mgr)
        self.plugin_names = self.plugins_mgr.names()
        self.plugins_by_id = {p.plugin._test_id: p for p in self.plugins}

    def load_formatters(self, formatters_namespace):
        self.formatters_mgr = extension.ExtensionManager(
            namespace=formatters_namespace,
            # We don't want to call the formatter when we load it.
            invoke_on_load=False,
            # We don't care if the extension doesn't have the dependencies it
            # needs to start up.
            verify_requirements=False,
            )

    def load_plugins(self, plugins_namespace):
        # See comments in load_formatters for parameter explanations
        self.plugins_mgr = extension.ExtensionManager(
            namespace=plugins_namespace,
            invoke_on_load=False,
            verify_requirements=False,
            )


# Using entry-points and pkg_resources *can* be expensive. So let's load these
# once, store them on the object, and have a module global object for
# accessing them. After the first time this module is imported, it should save
# this attribute on the module and not have to reload the entry-points.
MANAGER = Manager()
