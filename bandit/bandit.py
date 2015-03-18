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

import argparse
import logging
import sys

from core import manager as b_manager


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
        help='group results by (vuln)erability type or (file) it occurs in'
    )
    parser.add_argument(
        '-n', '--number', dest='context_lines',
        action='store', default=0, type=int,
        help='number of context lines to print'
    )
    parser.add_argument(
        '-c', '--configfile', dest='config_file',
        action='store', default=default_test_config, type=str,
        help='test config file (default: %s)' % (
            default_test_config
        )
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
        choices=['txt', 'json']
    )
    parser.add_argument(
        '-o', '--output', dest='output_file', action='store',
        default=None, help='write report to filename'
    )
    parser.add_argument(
        '-d', '--debug', dest='debug', action='store_true',
        help='turn on debug mode'
    )
    parser.set_defaults(debug=False)

    # setup work - parse arguments, and initialize BanditManager
    args = parser.parse_args()
    b_mgr = b_manager.BanditManager(args.config_file, args.agg_type,
                                    args.debug, profile_name=args.profile)

    # we getLogger() here because BanditManager has configured it at this point
    logger = logging.getLogger()
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
