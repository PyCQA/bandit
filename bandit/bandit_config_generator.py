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
import logging
import sys

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


def write_config_file(config, f):
    f.write('# Generated using %s\n' % PROG_NAME)

    # Start by writing profiles
    f.write(yaml.dump({'profiles': config['profiles']},
                      default_flow_style=False))

    # Write the rest of the config.
    for key in config:
        if key == 'profiles':
            continue
        f.write('\n')
        f.write(yaml.dump({key: config[key]}, default_flow_style=False))


def clean_profile(config, profile_name):
    """Remove all profiles but the most generic one.

    Removes all profiles from CONFIG except the 'All' one, renamed to
    PROFILE_NAME.
    """
    config['profiles'] = {
        profile_name: config['profiles']['All']
    }
    return config


def disable_checkers(config, disabled_checkers):
    """Disable checkers specified using DISABLED_CHECKERS from CONFIG."""
    logger.info('Disabling the following checkers: %s' %
                ', '.join(disabled_checkers))
    for profile in config['profiles']:
        includes = [x for x in config['profiles'][profile]['include']
                    if x not in disabled_checkers]
        config['profiles'][profile]['include'] = includes
        config['profiles'][profile]['exclude'] = disabled_checkers

    for test in disabled_checkers:
        # Some tests do not have extra configuration.
        if config.pop(test, None) is not None:
            logger.info('Disabled configuration for "%s"' % test)

    return config


def parse_args():
    parser = argparse.ArgumentParser(description='Generate a bandit config')
    parser.add_argument('--out', default='bandit.yaml',
                        help='output file')
    parser.add_argument('default_config_file',
                        help='a generic config file as provided by bandit')
    parser.add_argument('user_config_file',
                        help='user config file')
    args = parser.parse_args()
    return args


def read_yaml_file(filename):
    try:
        with open(filename) as f:
            return yaml.safe_load(f)
    except IOError:
        print("Could not open %s" % filename, file=sys.stderr)
        sys.exit(1)


def main():
    init_logger()
    args = parse_args()

    default_config = read_yaml_file(args.default_config_file)
    user_config = read_yaml_file(args.user_config_file)

    config = clean_profile(default_config,
                           user_config.get('profile_name', 'default'))
    if 'exclude_checkers' in user_config:
        config = disable_checkers(config, user_config['exclude_checkers'])

    try:
        with open(args.out, 'w') as f:
            write_config_file(config, f)
    except IOError:
        print("Could not write to %s" % args.out, file=sys.stderr)
        sys.exit(1)

    return 0


if __name__ == '__main__':
    sys.exit(main())
