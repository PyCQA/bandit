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
import os
import sys

import yaml

from bandit.core import extension_loader

PROG_NAME = 'bandit_conf_generator'
logger = logging.getLogger(__name__)


template = """
### config may optionally select or skip tests

# (optional) list included tests here:
{test}

# (optional) list skipped tests here:
{skip}

### override settings - used to set settings for plugins to non-default values

{settings}
"""


def init_logger():
    logger.handlers = []
    log_level = logging.INFO
    log_format_string = "[%(levelname)5s]: %(message)s"
    logging.captureWarnings(True)
    logger.setLevel(log_level)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(log_format_string))
    logger.addHandler(handler)


def parse_args():
    help_description = """Bandit Config Generator

    This tool is used to generate an optional profile.  The profile may be used
    to include or skip tests and override values for plugins.

    When used to store an output profile, this tool will output a template that
    includes all plugins and their default settings.  Any settings which aren't
    being overridden can be safely removed from the profile and default values
    will be used.  Bandit will prefer settings from the profile over the built
    in values."""

    parser = argparse.ArgumentParser(
        description=help_description,
        formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('--show-defaults', dest='show_defaults',
                        action='store_true',
                        help='show the default settings values for each '
                             'plugin but do not output a profile')
    parser.add_argument('-o', '--out', dest='output_file',
                        action='store',
                        help='output file to save profile')
    parser.add_argument(
        '-t', '--tests', dest='tests',
        action='store', default=None, type=str,
        help='list of test names to run')
    parser.add_argument(
        '-s', '--skip', dest='skips',
        action='store', default=None, type=str,
        help='list of test names to skip')
    args = parser.parse_args()
    return args


def get_config_settings():
    config = {}
    for plugin in extension_loader.MANAGER.plugins:
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

    yaml_settings = get_config_settings()

    if args.show_defaults:
        print(yaml_settings)

    if args.output_file:
        if os.path.exists(os.path.abspath(args.output_file)):
            logger.error("File %s already exists, exiting", args.output_file)
            sys.exit(2)

        try:
            with open(args.output_file, 'w') as f:
                skips = args.skips.split(',') if args.skips else []
                tests = args.tests.split(',') if args.tests else []

                for skip in skips:
                    if not extension_loader.MANAGER.check_id(skip):
                        raise RuntimeError('unknown ID in skips: %s' % skip)

                for test in tests:
                    if not extension_loader.MANAGER.check_id(test):
                        raise RuntimeError('unknown ID in tests: %s' % test)

                contents = template.format(
                    settings=yaml_settings,
                    skip='skips: ' + str(skips) if skips else '',
                    test='tests: ' + str(tests) if tests else '')
                f.write(contents)

        except IOError:
            logger.error("Unable to open %s for writing", args.output_file)

        except Exception as e:
            logger.error("Error: %s", e)

        else:
            logger.info("Successfully wrote profile: %s", args.output_file)

    return 0


if __name__ == '__main__':
    sys.exit(main())
