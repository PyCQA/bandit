#
# SPDX-License-Identifier: Apache-2.0
import sys

from stevedore import extension

from bandit.core import utils


class Manager:
    # These IDs are for bandit built in tests
    builtin = ["B001"]  # Built in blacklist test

    def __init__(
        self,
        formatters_namespace="bandit.formatters",
        plugins_namespace="bandit.plugins",
        blacklists_namespace="bandit.blacklists",
    ):
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
                print(
                    "WARNING: Test '%s' has no ID, skipping." % plugin.name,
                    file=sys.stderr,
                )
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
        for val in self.blacklist.values():
            for b in val:
                self.blacklist_by_id[b["id"]] = b
                self.blacklist_by_name[b["name"]] = b

    def validate_profile(self, profile):
        """Validate that everything in the configured profiles looks good."""
        for inc in profile["include"]:
            if not self.check_id(inc):
                raise ValueError("Unknown test found in profile: %s" % inc)

        for exc in profile["exclude"]:
            if not self.check_id(exc):
                raise ValueError("Unknown test found in profile: %s" % exc)

        union = set(profile["include"]) & set(profile["exclude"])
        if len(union) > 0:
            raise ValueError(
                "Non-exclusive include/exclude test sets: %s" % union
            )

    def check_id(self, test):
        return (
            test in self.plugins_by_id
            or test in self.blacklist_by_id
            or test in self.builtin
        )


# Using entry-points and pkg_resources *can* be expensive. So let's load these
# once, store them on the object, and have a module global object for
# accessing them. After the first time this module is imported, it should save
# this attribute on the module and not have to reload the entry-points.
MANAGER = Manager()
