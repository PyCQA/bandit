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

import sys

import yaml

from bandit.core import constants


class BanditConfig():

    _config = dict()
    _logger = None
    _settings = dict()

    def __init__(self, logger, config_file):
        '''Attempt to initialize a config dictionary from a yaml file.

        Error out if loading the yaml file fails for any reason.
        :param logger: Logger to be used in the case of errors
        :param config_file: The Bandit yaml config file
        :return: -
        '''

        self._logger = logger

        try:
            f = open(config_file, 'r')
        except IOError:
            logger.error("could not open config file: %s", config_file)
            sys.exit(2)
        else:
            try:
                self._config = yaml.safe_load(f)
            except yaml.YAMLError:
                logger.error("Invalid config file specified: %s", config_file)
                sys.exit(2)

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
            if level in cur_item:
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
        self._init_progress_increment()
        self._init_output_colors()
        self._init_plugin_name_pattern()

    def _init_progress_increment(self):
        '''Sets settings['progress'] from default or config file.'''
        progress = constants.progress_increment
        if self.get_option('show_progress_every'):
            progress = self.get_option('show_progress_every')
        self._settings['progress'] = progress

    def _init_output_colors(self):
        '''Sets the settings colors

        sets settings['color_xxx'] where xxx is DEFAULT, HEADER, LOW, MEDIUM,
        HIGH
        '''
        colors = ['HEADER', 'DEFAULT', 'LOW', 'MEDIUM', 'HIGH']
        color_settings = dict()

        isatty = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

        for color in colors:
            # if not a TTY, overwrite color codes in configuration
            if not isatty:
                color_settings[color] = ""
            # else read color codes in from the config
            else:
                # grab the default color from constant
                color_settings[color] = constants.color[color]

                # check if the option has been set in config file
                options_string = 'output_colors.' + color
                if self.get_option(options_string):
                    color_string = self.get_option(options_string)
                    # some manipulation is needed because escape string doesn't
                    # come back from yaml correctly
                    if color_string.find('['):
                        right_half = color_string[color_string.find('['):]
                        left_half = '\033'
                        color_settings[color] = left_half + right_half

            # update the settings dict with the color value
            settings_string = 'color_' + color
            self._settings[settings_string] = color_settings[color]

    def _init_plugin_name_pattern(self):
        '''Sets settings['plugin_name_pattern'] from default or config file.'''
        plugin_name_pattern = constants.plugin_name_pattern
        if self.get_option('plugin_name_pattern'):
            plugin_name_pattern = self.get_option('plugin_name_pattern')
        self._settings['plugin_name_pattern'] = plugin_name_pattern
