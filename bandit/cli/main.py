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
import sysconfig

import appdirs
import six

import bandit
from bandit.core import config as b_config
from bandit.core import constants
from bandit.core import manager as b_manager
from bandit.core import utils


BASE_CONFIG = 'bandit.yaml'
logger = logging.getLogger()


def _init_logger(debug=False, log_format=None):
    '''Initialize the logger

    :param debug: Whether to enable debug mode
    :return: An instantiated logging instance
    '''
    logger.handlers = []
    log_level = logging.INFO
    if debug:
        log_level = logging.DEBUG

    if not log_format:
        # default log format
        log_format_string = constants.log_format_string
    else:
        log_format_string = log_format

    logging.captureWarnings(True)

    logger.setLevel(log_level)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(log_format_string))
    logger.addHandler(handler)
    logger.debug("logging initialized")


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
            logger.error('Multiple .bandit files found - scan separately or '
                         'choose one with --ini\n\t%s',
                         ', '.join(bandit_files))
            sys.exit(2)

        elif len(bandit_files) == 1:
            ini_file = bandit_files[0]
            logger.info('Found project level .bandit file: %s',
                        bandit_files[0])

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
        logger.info("Using command line arg for %s", option_name)
        return arg_val
    elif ini_val:
        logger.info("Using .bandit arg for %s", option_name)
        return ini_val
    else:
        return None


def _running_under_virtualenv():
    if hasattr(sys, 'real_prefix'):
        return True
    elif sys.prefix != getattr(sys, 'base_prefix', sys.prefix):
        return True


def _find_config():
    # prefer config file in the following order:
    # 1) current directory, 2) user home directory, 3) bundled config
    config_dirs = (
        ['.'] + [appdirs.user_config_dir("bandit")] +
        appdirs.site_config_dir("bandit", multipath=True).split(':'))
    if _running_under_virtualenv():
        config_dirs.append(os.path.join(sys.prefix, 'etc', 'bandit'))
        config_dirs.append(
            os.path.join(sysconfig.get_paths().get('purelib', ''),
                         'bandit', 'config'))
    config_locations = [os.path.join(s, BASE_CONFIG) for s in config_dirs]

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
    _init_logger(debug)
    # By default path would be /etx/xdg/bandit, we want system paths
    os.environ['XDG_CONFIG_DIRS'] = '/etc:/usr/local/etc'
    extension_mgr = _init_extensions()

    baseline_formatters = [f.name for f in filter(lambda x:
                                                  hasattr(x.plugin,
                                                          '_accepts_baseline'),
                                                  extension_mgr.formatters)]

    # now do normal startup
    parser = argparse.ArgumentParser(
        description='Bandit - a Python source code analyzer.',
        formatter_class=argparse.RawDescriptionHelpFormatter
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
        action='store', default=3, type=int,
        help='max number of code lines to display for each issue identified'
    )
    parser.add_argument(
        '-c', '--configfile', dest='config_file',
        action='store', default=None, type=str,
        help=('if omitted default locations are checked. '
              'Check documentation for searched paths')
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        '-p', '--profile', dest='profile',
        action='store', default=None, type=str,
        help='test set profile in config to use (defaults to all tests)'
    )
    group.add_argument(
        '-t', '--tests', dest='tests',
        action='store', default=None, type=str,
        help='list of test names to run'
    )
    group.add_argument(
        '-s', '--skip', dest='skips',
        action='store', default=None, type=str,
        help='list of test names to skip'
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
        default='screen', help='specify output format',
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
    parser.add_argument(
        '--ignore-nosec', dest='ignore_nosec', action='store_true',
        help='do not skip lines with # nosec comments'
    )
    parser.add_argument(
        '-x', '--exclude', dest='excluded_paths', action='store',
        default='', help='Comma separated list of paths to exclude from scan. '
                         'Note that these are in addition to the excluded '
                         'paths provided in the config file.'
    )
    parser.add_argument(
        '-b', '--baseline', dest='baseline', action='store',
        default=None, help='Path to a baseline report, in JSON format. '
                           'Note: baseline reports must be output in one of '
                           'the following formats: ' + str(baseline_formatters)
    )
    parser.add_argument(
        '--ini', dest='ini_path', action='store', default=None,
        help='Path to a .bandit file which supplies command line arguments to '
             'Bandit.'
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

    plugin_list = '\n\t'.join(sorted(plugin_info))
    parser.epilog = ('The following plugin suites were discovered and'
                     ' loaded:\n\t{0}\n'.format(plugin_list))

    # setup work - parse arguments, and initialize BanditManager
    args = parser.parse_args()
    config_file = args.config_file
    if not config_file:
        try:
            config_file = _find_config()
        except utils.NoConfigFileFound as e:
            logger.error(e)
            sys.exit(2)

    try:
        b_conf = b_config.BanditConfig(config_file)
    except (utils.ConfigFileUnopenable, utils.ConfigFileInvalidYaml) as e:
        logger.error('%s', e)
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

    if args.tests:
        test_list = args.tests.split(',')
        test_set = set(test_list)
        all_set = set(extension_mgr.plugins_by_id)
        if not test_set.issubset(all_set):
            unknown_tests = ','.join(test_set - all_set)
            logger.error("Unknown test ID(s) in test list: %s", unknown_tests)
            sys.exit(2)
        profile_name = test_list
    elif args.skips:
        skip_list = args.skips.split(',')
        skip_set = set(skip_list)
        all_set = set(extension_mgr.plugins_by_id)
        if not skip_set.issubset(all_set):
            unknown_tests = ','.join(skip_set - all_set)
            logger.error("Unknown test ID(s) in skip list: %s", unknown_tests)
            sys.exit(2)
        profile_name = list(all_set - skip_set)
    else:
        profile_name = args.profile

    try:
        b_mgr = b_manager.BanditManager(b_conf, args.agg_type, args.debug,
                                        profile_name=profile_name,
                                        verbose=args.verbose,
                                        ignore_nosec=args.ignore_nosec)
    except utils.ProfileNotFound as e:
        logger.error(e)
        sys.exit(2)

    if args.baseline is not None:
        try:
            with open(args.baseline) as bl:
                data = bl.read()
                b_mgr.populate_baseline(data)
        except IOError:
            logger.warning("Could not open baseline report: %s", args.baseline)
            sys.exit(2)

        if args.output_format not in baseline_formatters:
            logger.warning('Baseline must be used with one of the following '
                           'formats: ' + str(baseline_formatters))
            sys.exit(2)

    if args.output_format != "json":
        logger.info("using config: %s", config_file)
        logger.info("running on Python %d.%d.%d", sys.version_info.major,
                    sys.version_info.minor, sys.version_info.micro)

    # initiate file discovery step within Bandit Manager
    b_mgr.discover_files(args.targets, args.recursive, args.excluded_paths)

    if not b_mgr.b_ts.tests:
        logger.error('No tests would be run, please check the profile.')
        sys.exit(2)

    # initiate execution of tests within Bandit Manager
    b_mgr.run_tests()
    logger.debug(b_mgr.b_ma)
    logger.debug(b_mgr.metrics)

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
