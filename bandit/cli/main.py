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
import fnmatch
import logging
import os
import sys

import six

import bandit
from bandit.core import config as b_config
from bandit.core import constants
from bandit.core import manager as b_manager
from bandit.core import utils


BASE_CONFIG = 'bandit.yaml'
LOG = logging.getLogger()


def _init_logger(debug=False, log_format=None):
    '''Initialize the logger

    :param debug: Whether to enable debug mode
    :return: An instantiated logging instance
    '''
    LOG.handlers = []
    log_level = logging.INFO
    if debug:
        log_level = logging.DEBUG

    if not log_format:
        # default log format
        log_format_string = constants.log_format_string
    else:
        log_format_string = log_format

    logging.captureWarnings(True)

    LOG.setLevel(log_level)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(log_format_string))
    LOG.addHandler(handler)
    LOG.debug("logging initialized")


def _get_options_from_ini(ini_path, target):
    """Return a dictionary of config options or None if we can't load any."""
    ini_file = None

    if ini_path:
        ini_file = ini_path
    else:
        bandit_files = []

        for t in target:
            for root, dirnames, filenames in os.walk(t):
                for filename in fnmatch.filter(filenames, '.bandit'):
                    bandit_files.append(os.path.join(root, filename))

        if len(bandit_files) > 1:
            LOG.error('Multiple .bandit files found - scan separately or '
                      'choose one with --ini\n\t%s', ', '.join(bandit_files))
            sys.exit(2)

        elif len(bandit_files) == 1:
            ini_file = bandit_files[0]
            LOG.info('Found project level .bandit file: %s', bandit_files[0])

    if ini_file:
        return utils.parse_ini_file(ini_file)
    else:
        return None


def _init_extensions():
    from bandit.core import extension_loader as ext_loader
    return ext_loader.MANAGER


def _log_option_source(arg_val, ini_val, option_name):
    """It's useful to show the source of each option."""
    if arg_val:
        LOG.info("Using command line arg for %s", option_name)
        return arg_val
    elif ini_val:
        LOG.info("Using .bandit arg for %s", option_name)
        return ini_val
    else:
        return None


def _running_under_virtualenv():
    if hasattr(sys, 'real_prefix'):
        return True
    elif sys.prefix != getattr(sys, 'base_prefix', sys.prefix):
        return True


def _get_profile(config, profile_name, config_path):
    profile = {}
    if profile_name:
        profiles = config.get_option('profiles') or {}
        profile = profiles.get(profile_name)
        if profile is None:
            raise utils.ProfileNotFound(config_path, profile_name)
        LOG.debug("read in legacy profile '%s': %s", profile_name, profile)
    else:
        profile['include'] = set(config.get_option('tests') or [])
        profile['exclude'] = set(config.get_option('skips') or [])
    return profile


def _log_info(args, profile):
    inc = ",".join([t for t in profile['include']]) or "None"
    exc = ",".join([t for t in profile['exclude']]) or "None"
    LOG.info("profile include tests: %s", inc)
    LOG.info("profile exclude tests: %s", exc)
    LOG.info("cli include tests: %s", args.tests)
    LOG.info("cli exclude tests: %s", args.skips)


def main():
    # bring our logging stuff up as early as possible
    debug = ('-d' in sys.argv or '--debug' in sys.argv)
    _init_logger(debug)
    extension_mgr = _init_extensions()

    baseline_formatters = [f.name for f in filter(lambda x:
                                                  hasattr(x.plugin,
                                                          '_accepts_baseline'),
                                                  extension_mgr.formatters)]

    # now do normal startup
    parser = argparse.ArgumentParser(
        description='Bandit - a Python source code security analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        'targets', metavar='targets', type=str, nargs='+',
        help='source file(s) or directory(s) to be tested'
    )
    parser.add_argument(
        '-r', '--recursive', dest='recursive',
        action='store_true', help='find and process files in subdirectories'
    )
    parser.add_argument(
        '-a', '--aggregate', dest='agg_type',
        action='store', default='file', type=str,
        choices=['file', 'vuln'],
        help='aggregate output by vulnerability (default) or by filename'
    )
    parser.add_argument(
        '-n', '--number', dest='context_lines',
        action='store', default=3, type=int,
        help='maximum number of code lines to output for each issue'
    )
    parser.add_argument(
        '-c', '--configfile', dest='config_file',
        action='store', default=None, type=str,
        help='optional config file to use for selecting plugins and '
             'overriding defaults'
    )
    parser.add_argument(
        '-p', '--profile', dest='profile',
        action='store', default=None, type=str,
        help='profile to use (defaults to executing all tests)'
    )
    parser.add_argument(
        '-t', '--tests', dest='tests',
        action='store', default=None, type=str,
        help='comma-separated list of test IDs to run'
    )
    parser.add_argument(
        '-s', '--skip', dest='skips',
        action='store', default=None, type=str,
        help='comma-separated list of test IDs to skip'
    )
    parser.add_argument(
        '-l', '--level', dest='severity', action='count',
        default=1, help='report only issues of a given severity level or '
                        'higher (-l for LOW, -ll for MEDIUM, -lll for HIGH)'
    )
    parser.add_argument(
        '-i', '--confidence', dest='confidence', action='count',
        default=1, help='report only issues of a given confidence level or '
                        'higher (-i for LOW, -ii for MEDIUM, -iii for HIGH)'
    )
    output_format = 'screen' if sys.stdout.isatty() else 'txt'
    parser.add_argument(
        '-f', '--format', dest='output_format', action='store',
        default=output_format, help='specify output format',
        choices=sorted(extension_mgr.formatter_names)
    )
    parser.add_argument(
        '-o', '--output', dest='output_file', action='store', nargs='?',
        type=argparse.FileType('w'), default=sys.stdout,
        help='write report to filename'
    )
    parser.add_argument(
        '-v', '--verbose', dest='verbose', action='store_true',
        help='output extra information like excluded and included files'
    )
    parser.add_argument(
        '-d', '--debug', dest='debug', action='store_true',
        help='turn on debug mode'
    )
    parser.add_argument(
        '--ignore-nosec', dest='ignore_nosec', action='store_true',
        help='do not skip lines with # nosec comments'
    )
    parser.add_argument(
        '-x', '--exclude', dest='excluded_paths', action='store',
        default='', help='comma-separated list of paths to exclude from scan '
                         '(note that these are in addition to the excluded '
                         'paths provided in the config file)'
    )
    parser.add_argument(
        '-b', '--baseline', dest='baseline', action='store',
        default=None, help='path of a baseline report to compare against '
                           '(only JSON-formatted files are accepted)'
    )
    parser.add_argument(
        '--ini', dest='ini_path', action='store', default=None,
        help='path to a .bandit file that supplies command line arguments'
    )
    parser.add_argument(
        '--version', action='version',
        version='%(prog)s {version}'.format(version=bandit.__version__)
    )
    parser.set_defaults(debug=False)
    parser.set_defaults(verbose=False)
    parser.set_defaults(ignore_nosec=False)

    plugin_info = ["%s\t%s" % (a[0], a[1].name) for a in
                   six.iteritems(extension_mgr.plugins_by_id)]
    blacklist_info = []
    for a in six.iteritems(extension_mgr.blacklist):
        for b in a[1]:
            blacklist_info.append('%s\t%s' % (b['id'], b['name']))

    plugin_list = '\n\t'.join(sorted(set(plugin_info + blacklist_info)))
    parser.epilog = ('The following tests were discovered and'
                     ' loaded:\n\t{0}\n'.format(plugin_list))

    # setup work - parse arguments, and initialize BanditManager
    args = parser.parse_args()

    try:
        b_conf = b_config.BanditConfig(config_file=args.config_file)
    except utils.ConfigError as e:
        LOG.error(e)
        sys.exit(2)

    # Handle .bandit files in projects to pass cmdline args from file
    ini_options = _get_options_from_ini(args.ini_path, args.targets)
    if ini_options:
        # prefer command line, then ini file
        args.excluded_paths = _log_option_source(args.excluded_paths,
                                                 ini_options.get('exclude'),
                                                 'excluded paths')

        args.skips = _log_option_source(args.skips, ini_options.get('skips'),
                                        'skipped tests')

        args.tests = _log_option_source(args.tests, ini_options.get('tests'),
                                        'selected tests')
        # TODO(tmcpeak): any other useful options to pass from .bandit?

    # if the log format string was set in the options, reinitialize
    if b_conf.get_option('log_format'):
        log_format = b_conf.get_option('log_format')
        _init_logger(debug, log_format=log_format)

    try:
        profile = _get_profile(b_conf, args.profile, args.config_file)
        _log_info(args, profile)

        profile['include'].update(args.tests.split(',') if args.tests else [])
        profile['exclude'].update(args.skips.split(',') if args.skips else [])
        extension_mgr.validate_profile(profile)

    except (utils.ProfileNotFound, ValueError) as e:
        LOG.error(e)
        sys.exit(2)

    b_mgr = b_manager.BanditManager(b_conf, args.agg_type, args.debug,
                                    profile=profile, verbose=args.verbose,
                                    ignore_nosec=args.ignore_nosec)

    if args.baseline is not None:
        try:
            with open(args.baseline) as bl:
                data = bl.read()
                b_mgr.populate_baseline(data)
        except IOError:
            LOG.warning("Could not open baseline report: %s", args.baseline)
            sys.exit(2)

        if args.output_format not in baseline_formatters:
            LOG.warning('Baseline must be used with one of the following '
                        'formats: ' + str(baseline_formatters))
            sys.exit(2)

    if args.output_format != "json":
        if args.config_file:
            LOG.info("using config: %s", args.config_file)

        LOG.info("running on Python %d.%d.%d", sys.version_info.major,
                 sys.version_info.minor, sys.version_info.micro)

    # initiate file discovery step within Bandit Manager
    b_mgr.discover_files(args.targets, args.recursive, args.excluded_paths)

    if not b_mgr.b_ts.tests:
        LOG.error('No tests would be run, please check the profile.')
        sys.exit(2)

    # initiate execution of tests within Bandit Manager
    b_mgr.run_tests()
    LOG.debug(b_mgr.b_ma)
    LOG.debug(b_mgr.metrics)

    # trigger output of results by Bandit Manager
    sev_level = constants.RANKING[args.severity - 1]
    conf_level = constants.RANKING[args.confidence - 1]
    b_mgr.output_results(args.context_lines,
                         sev_level,
                         conf_level,
                         args.output_file,
                         args.output_format)

    # return an exit code of 1 if there are results, 0 otherwise
    if b_mgr.results_count(sev_filter=sev_level, conf_filter=conf_level) > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
