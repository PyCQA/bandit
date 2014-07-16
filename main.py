#!/usr/bin/env python

import sys, argparse
from bandit import manager as b_manager


if __name__=='__main__':
    parser = argparse.ArgumentParser(description='Bandit - a Python source code analyzer.')
    parser.add_argument('files', metavar='file', type=str, nargs='+',
                       help='source file/s to be tested')
    parser.add_argument('-C', '--context', dest='context', action='store',
                       default=0, type=int,
                       help='number of context lines to print')
    parser.add_argument('-l', '--level', dest='level', action='count',
                       default=1, help='results level filter')
    parser.add_argument('-d', '--debug', dest='debug', action='store_true',
                        help='turn on debug mode')
    parser.set_defaults(debug=False)

    args = parser.parse_args()

    b_mgr = b_manager.BanditManager(args.debug)
    b_mgr.run_scope(args.files)
    b_mgr.output_results(args.context, args.level - 1)
    #b_mgr.output_metaast()


