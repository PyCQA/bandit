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

from bandit.core import manager as b_manager

default_test_config = 'bandit.yaml'


def main():
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
        help=('test config file, defaults to /etc/bandit/bandit.yaml, or'
              './bandit.yaml if not given')
    )
    parser.add_argument(
        '-p', '--profile', dest='profile',
        action='store', default=None, type=str,
        help='test set profile in config to use (defaults to all tests)'
    )
    parser.add_argument(
        '-l', '--level', dest='level', action='count',
        default=1, help='results level filter'
    )
    parser.add_argument(
        '-f', '--format', dest='output_format', action='store',
        default='txt', help='specify output format',
        choices=['txt', 'json', 'csv', 'xml']
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

    # setup work - parse arguments, and initialize BanditManager
    args = parser.parse_args()
    config_file = args.config_file
    if not config_file:

        home_config = None

        # attempt to get the home directory from environment
        home_dir = os.environ.get('HOME')
        if home_dir:
            home_config = "%s/.config/bandit/%s" % (home_dir,
                                                    default_test_config)

        installed_config = str(os.path.dirname(os.path.realpath(__file__)) +
                               '/config/%s' % default_test_config)

        # prefer config file in the following order:
        # 1) current directory, 2) user home directory, 3) bundled config
        config_paths = [default_test_config, home_config, installed_config]

        for path in config_paths:
            if path and os.access(path, os.R_OK):
                config_file = path
                break

    if not config_file:
        # no logger yet, so using print
        print ("no config found, tried ...")
        for path in config_paths:
            if path:
                print ("\t%s" % path)
        sys.exit(2)

    b_mgr = b_manager.BanditManager(config_file, args.agg_type,
                                    args.debug, profile_name=args.profile,
                                    verbose=args.verbose)
    # we getLogger() here because BanditManager has configured it at this point
    logger = logging.getLogger()
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

    # initiate file discovery step within Bandit Manager
    b_mgr.discover_files(args.targets, args.recursive)

    # initiate execution of tests within Bandit Manager
    b_mgr.run_tests()
    if args.debug:
        b_mgr.output_metaast()

    # trigger output of results by Bandit Manager
    b_mgr.output_results(args.context_lines, args.level - 1, args.output_file,
                         args.output_format)

    # return an exit code of 1 if there are results, 0 otherwise
    if b_mgr.results_count > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
