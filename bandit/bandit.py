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
from __future__ import absolute_import

import argparse
import logging
import os
import sys

from appdirs import site_config_dir
from appdirs import user_config_dir

from bandit.core import manager as b_manager
from bandit.core import utils

BASE_CONFIG = '/bandit.yaml'


def _init_logger(debug=False, log_format=None):
    '''Initialize the logger

    :param debug: Whether to enable debug mode
    :return: An instantiated logging instance
    '''
    log_level = logging.INFO
    if debug:
        log_level = logging.DEBUG

    if not log_format:
        # default log format
        log_format_string = '[%(module)s]\t%(levelname)s\t%(message)s'
    else:
        log_format_string = log_format

    logger = logging.getLogger()
    logger.setLevel(log_level)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(log_format_string))
    logger.addHandler(handler)
    logger.debug("logging initialized")
    return logger


def _init_extensions():
    from bandit.core import extension_loader as ext_loader
    return ext_loader.MANAGER


def _find_config():
    # prefer config file in the following order:
    # 1) current directory, 2) user home directory, 3) bundled config
    config_dirs = (['.'] + [user_config_dir("bandit")] +
                   site_config_dir("bandit", multipath=True).split(':'))
    config_locations = [s + BASE_CONFIG for s in config_dirs]

    # pip on Mac installs to the following path, but appdirs expects to
    # follow Mac's BPFileSystem spec which doesn't include this path so
    # we'll insert it. Issue raised as http://git.io/vOreU
    mac_pip_cfg_path = "/usr/local/etc/bandit/bandit.yaml"
    if mac_pip_cfg_path not in config_locations:
        config_locations.append(mac_pip_cfg_path)

    for config_file in config_locations:
        if os.path.isfile(config_file):
            return config_file  # Found a valid config
    else:
        # Failed to find any config, raise an error.
        raise utils.NoConfigFileFound(config_locations)


def main():
    # bring our logging stuff up as early as possible
    debug = ('-d' in sys.argv or '--debug' in sys.argv)
    logger = _init_logger(debug)
    # By default path would be /etx/xdg/bandit, we want system paths
    os.environ['XDG_CONFIG_DIRS'] = '/etc:/usr/local/etc'
    extension_mgr = _init_extensions()

    # now do normal startup
    parser = argparse.ArgumentParser(
        description='Bandit - a Python source code analyzer.'
    )
    parser.add_argument(
        'targets', metavar='targets', type=str, nargs='+',
        help='source file(s) or directory(s) to be tested'
    )
    parser.add_argument(
        '-r', '--recursive', dest='recursive',
        action='store_true', help='process files in subdirectories'
    )
    parser.add_argument(
        '-a', '--aggregate', dest='agg_type',
        action='store', default='file', type=str,
        choices=['file', 'vuln'],
        help='group results by vulnerability type or file it occurs in'
    )
    parser.add_argument(
        '-n', '--number', dest='context_lines',
        action='store', default=-1, type=int,
        help='max number of code lines to display for each issue identified'
    )
    parser.add_argument(
        '-c', '--configfile', dest='config_file',
        action='store', default=None, type=str,
        help=('if omitted default locations are checked. '
              'Check documentation for searched paths')
    )
    parser.add_argument(
        '-p', '--profile', dest='profile',
        action='store', default=None, type=str,
        help='test set profile in config to use (defaults to all tests)'
    )
    parser.add_argument(
        '-l', '--level', dest='severity', action='count',
        default=1, help=('results severity filter. Show only issues of a given'
                         ' severity level or higher. -l for LOW,'
                         ' -ll for MEDIUM, -lll for HIGH')
    )
    parser.add_argument(
        '-i', '--confidence', dest='confidence', action='count',
        default=1, help='confidence results filter, show only issues of this '
                        'level or higher. -i for LOW, -ii for MEDIUM, '
                        '-iii for HIGH'
    )
    parser.add_argument(
        '-f', '--format', dest='output_format', action='store',
        default='txt', help='specify output format',
        choices=sorted(extension_mgr.formatter_names)
    )
    parser.add_argument(
        '-o', '--output', dest='output_file', action='store',
        default=None, help='write report to filename'
    )
    parser.add_argument(
        '-v', '--verbose', dest='verbose', action='store_true',
        help='show extra information like excluded and included files'
    )
    parser.add_argument(
        '-d', '--debug', dest='debug', action='store_true',
        help='turn on debug mode'
    )
    parser.set_defaults(debug=False)
    parser.set_defaults(verbose=False)

    parser.epilog = ('The following plugin suites were discovered and'
                     ' loaded: [' +
                     ', '.join(extension_mgr.plugin_names) + ']')

    # setup work - parse arguments, and initialize BanditManager
    args = parser.parse_args()
    config_file = args.config_file
    if not config_file:
        try:
            config_file = _find_config()
        except utils.NoConfigFileFound as e:
            logger.error(e)
            sys.exit(2)

    b_mgr = b_manager.BanditManager(config_file, args.agg_type,
                                    args.debug, profile_name=args.profile,
                                    verbose=args.verbose)

    if args.output_format != "json":
        logger.info("using config: %s", config_file)
        logger.info("running on Python %d.%d.%d", sys.version_info.major,
                    sys.version_info.minor, sys.version_info.micro)

    # check ability to write output file, if requested
    if args.output_file is not None:
        check_dest = b_mgr.check_output_destination(args.output_file)
        if check_dest is not True:
            logger.error(
                'Problem with specified output destination\n\t%s: %s',
                check_dest, args.output_file
            )
            sys.exit(2)

    # no point running if there are no tests available
    if not b_mgr.has_tests:
        logger.error('Could not find any tests to apply, please check '
                     'the configuration.')
        sys.exit(2)

    # initiate file discovery step within Bandit Manager
    b_mgr.discover_files(args.targets, args.recursive)

    # initiate execution of tests within Bandit Manager
    b_mgr.run_tests()
    if args.debug:
        b_mgr.output_metaast()

    # trigger output of results by Bandit Manager
    b_mgr.output_results(args.context_lines, args.severity - 1,
                         args.confidence - 1, args.output_file,
                         args.output_format)

    # return an exit code of 1 if there are results, 0 otherwise
    if b_mgr.results_count(sev_filter=args.severity - 1,
                           conf_filter=args.confidence - 1) > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
