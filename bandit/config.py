# -*- coding:utf-8 -*-
#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import sys
import yaml


class BanditConfig():

    _config = dict()

    def __init__(self, logger, config_file):
        '''
        Attempt to initialize a config dictionary from a yaml file, error out
        if this fails for any reason.
        :param logger: Logger to be used in the case of errors
        :param config_file: The Bandit yaml config file
        :return: -
        '''
        try:
            f = open(config_file, 'r')
        except IOError:
            logger.error("could not open config file: %s" % config_file)
            sys.exit(2)
        else:
            # yaml parser does its own exception handling
            self._config = yaml.load(f)

    @property
    def config(self):
        '''
        Property to return the config dictionary
        :return: Config dictionary
        '''
        return self._config
