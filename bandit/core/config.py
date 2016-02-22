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

import logging

import six
import yaml

from bandit.core import constants
from bandit.core import extension_loader
from bandit.core import utils


logger = logging.getLogger(__name__)


class BanditConfig():
    # These IDs are for bandit built in tests
    builtin = [
        'B001'  # Built in blacklist test
        ]

    def __init__(self, config_file=None):
        '''Attempt to initialize a config dictionary from a yaml file.

        Error out if loading the yaml file fails for any reason.
        :param config_file: The Bandit yaml config file

        :raises bandit.utils.ConfigFileUnopenable: If the config file cannot be
            opened.
        :raises bandit.utils.ConfigFileInvalidYaml: If the config file cannot
            be parsed.

        '''
        self.config_file = config_file
        self._config = {}

        if config_file:
            try:
                f = open(config_file, 'r')
            except IOError:
                raise utils.ConfigFileUnopenable(config_file)

            try:
                self._config = yaml.safe_load(f)
            except yaml.YAMLError:
                raise utils.ConfigFileInvalidYaml(config_file)

            # valid config must be a dict
            if not isinstance(self._config, dict):
                raise utils.ConfigFileInvalidYaml(config_file)

            self.convert_legacy_config()

        else:
            # use sane defaults
            self._config['plugin_name_pattern'] = '*.py'
            self._config['include'] = ['*.py', '*.pyw']

        self.validate_profiles()
        self._init_settings()

    def get_option(self, option_string):
        '''Returns the option from the config specified by the option_string.

        '.' can be used to denote levels, for example to retrieve the options
        from the 'a' profile you can use 'profiles.a'
        :param option_string: The string specifying the option to retrieve
        :return: The object specified by the option_string, or None if it can't
        be found.
        '''
        option_levels = option_string.split('.')
        cur_item = self._config
        for level in option_levels:
            if cur_item and (level in cur_item):
                cur_item = cur_item[level]
            else:
                return None

        return cur_item

    def get_setting(self, setting_name):
        if setting_name in self._settings:
            return self._settings[setting_name]
        else:
            return None

    @property
    def config(self):
        '''Property to return the config dictionary

        :return: Config dictionary
        '''
        return self._config

    def _init_settings(self):
        '''This function calls a set of other functions (one per setting)

        This function calls a set of other functions (one per setting) to build
        out the _settings dictionary.  Each other function will set values from
        the config (if set), otherwise use defaults (from constants if
        possible).
        :return: -
        '''
        self._settings = {}
        self._init_plugin_name_pattern()

    def _init_plugin_name_pattern(self):
        '''Sets settings['plugin_name_pattern'] from default or config file.'''
        plugin_name_pattern = constants.plugin_name_pattern
        if self.get_option('plugin_name_pattern'):
            plugin_name_pattern = self.get_option('plugin_name_pattern')
        self._settings['plugin_name_pattern'] = plugin_name_pattern

    def convert_legacy_config(self):
        updated_profiles = self.convert_names_to_ids()
        bad_calls, bad_imports = self.convert_legacy_blacklist_data()

        if updated_profiles:
            self.convert_legacy_blacklist_tests(updated_profiles,
                                                bad_calls, bad_imports)
            self._config['profiles'] = updated_profiles

    def convert_names_to_ids(self):
        '''Convert test names to IDs, unknown names are left unchanged.'''
        extman = extension_loader.MANAGER

        updated_profiles = {}
        for name, profile in six.iteritems(self.get_option('profiles') or {}):
            # NOTE(tkelsey): cant use default of get() because value is
            # sometimes explicity 'None', for example when the list if given in
            # yaml but not populated with any values.
            include = set((extman.get_plugin_id(i) or i)
                          for i in (profile.get('include') or []))
            exclude = set((extman.get_plugin_id(i) or i)
                          for i in (profile.get('exclude') or []))
            updated_profiles[name] = {'include': include, 'exclude': exclude}
        return updated_profiles

    def convert_legacy_blacklist_data(self):
        '''Detect legacy blacklist data and convert it to new format.'''
        bad_calls_list = []
        bad_imports_list = []

        bad_calls = self.get_option('blacklist_calls') or {}
        bad_calls = bad_calls.get('bad_name_sets', {})
        for item in bad_calls:
            for key, val in six.iteritems(item):
                val['name'] = key
                val['message'] = val['message'].replace('{func}', '{name}')
                bad_calls_list.append(val)

        bad_imports = self.get_option('blacklist_imports') or {}
        bad_imports = bad_imports.get('bad_import_sets', {})
        for item in bad_imports:
            for key, val in six.iteritems(item):
                val['name'] = key
                val['message'] = val['message'].replace('{module}', '{name}')
                val['qualnames'] = val['imports']
                del val['imports']
                bad_imports_list.append(val)

        if bad_imports_list or bad_calls_list:
            logger.warning('Legacy blacklist data found in config, '
                           'overriding data plugins')
        return bad_calls_list, bad_imports_list

    def convert_legacy_blacklist_tests(self, profiles, bad_imports, bad_calls):
        '''Detect old blacklist tests, convert to use new builtin.'''
        def _clean_set(name, data):
            if name in data:
                data.remove(name)
                data.add('B001')

        for name, profile in six.iteritems(profiles):
            blacklist = {}
            include = profile['include']
            exclude = profile['exclude']

            name = 'blacklist_calls'
            if name in include and name not in exclude:
                blacklist.setdefault('Call', []).extend(bad_calls)

            _clean_set(name, include)
            _clean_set(name, exclude)

            name = 'blacklist_imports'
            if name in include and name not in exclude:
                blacklist.setdefault('Import', []).extend(bad_imports)
                blacklist.setdefault('ImportFrom', []).extend(bad_imports)
                blacklist.setdefault('Call', []).extend(bad_imports)

            _clean_set(name, include)
            _clean_set(name, exclude)
            _clean_set('blacklist_import_func', include)
            _clean_set('blacklist_import_func', exclude)

            profile['blacklist'] = blacklist

    def validate_profiles(self):
        '''Validate that everything in the configured profiles looks good.'''
        extman = extension_loader.MANAGER

        for name, profile in six.iteritems(self._config.get('profiles', {})):
            for inc in profile['include']:
                if inc not in extman.plugins_by_id and inc not in self.builtin:
                    logger.warning('Unknown Test found in profile %s: %s',
                                   name, inc)

            for exc in profile['exclude']:
                if exc not in extman.plugins_by_id and exc not in self.builtin:
                    logger.warning('Unknown Test found in profile %s: %s',
                                   name, exc)
