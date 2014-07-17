#!/usr/bin/env python

import sys
import argparse
from bandit import manager as b_manager

default_test_config = 'bandit.ini'

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Bandit - a Python source code analyzer.'
    )
    parser.add_argument(
        'files', metavar='file', type=str, nargs='+',
        help='source file/s to be tested'
    )
    parser.add_argument(
        '-C', '--context', dest='context_lines',
        action='store', default=0, type=int,
        help='number of context lines to print'
    )
    parser.add_argument(
        '-t', '--testconfig', dest='test_config',
        action='store', default=default_test_config, type=str,
        help='test config file (default: %s)' % (
            default_test_config
        )
    )
    parser.add_argument(
        '-l', '--level', dest='level', action='count',
        default=1, help='results level filter'
    )
    parser.add_argument(
        '-d', '--debug', dest='debug', action='store_true',
        help='turn on debug mode'
    )
    parser.set_defaults(debug=False)

    args = parser.parse_args()

    b_mgr = b_manager.BanditManager(args.test_config, args.debug)
    b_mgr.run_scope(args.files)
    if args.debug:
        b_mgr.output_metaast()
    b_mgr.output_results(args.context_lines, args.level - 1)
