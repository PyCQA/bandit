# Copyright 2015 Red Hat Inc.
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

import argparse
import importlib
import logging
import sys

from stevedore import extension
import yaml

PROG_NAME = 'bandit_conf_generator'
logger = logging.getLogger(__name__)


def init_logger():
    logger.handlers = []
    log_level = logging.INFO
    log_format_string = "[bandit-config-generator] %(message)s"
    logging.captureWarnings(True)
    logger.setLevel(log_level)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(log_format_string))
    logger.addHandler(handler)


def parse_args():
    parser = argparse.ArgumentParser(
        description='Tool to display Bandit config options')

    parser.add_argument('--show-defaults', dest='show_defaults',
                        action='store_true',
                        help='show the default settings values for each '
                             'plugin')

    args = parser.parse_args()
    return args


def get_config_settings():
    """Print list of all plugins and default values of config."""
    plugins_mgr = extension.ExtensionManager(namespace='bandit.plugins',
                                             invoke_on_load=False,
                                             verify_requirements=False)
    logger.info('Successfully discovered %d plugins',
                len(plugins_mgr.extensions))

    config = {}

    for plugin in plugins_mgr.extensions:
        fn_name = plugin.name
        function = plugin.plugin

        # if a function takes config...
        if hasattr(function, '_takes_config'):
            fn_module = importlib.import_module(function.__module__)

            # call the config generator if it exists
            if hasattr(fn_module, 'gen_config'):
                config[fn_name] = fn_module.gen_config(function._takes_config)

    return yaml.safe_dump(config)


def main():
    init_logger()
    args = parse_args()

    if args.show_defaults:
        print(get_config_settings())

    return 0


if __name__ == '__main__':
    sys.exit(main())
