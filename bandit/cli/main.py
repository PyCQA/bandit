#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0
"""Bandit is a tool designed to find common security issues in Python code."""
import fnmatch
import logging
import os
import sys
import textwrap

from mininterface import run
from mininterface._lib.dataclass_creation import create_with_missing
from mininterface._lib.dataclass_creation import MISSING_NONPROP
from mininterface.tag.flag import Dir
from mininterface.tag.flag import File
from tyro.conf import arg
from tyro.conf import DisallowNone
from tyro.conf import FlagCreatePairsOff
from tyro.conf import Positional

import bandit
from .get_env import get_env
from .get_env import Level
from bandit.core import config as b_config
from bandit.core import constants
from bandit.core import manager as b_manager
from bandit.core import utils

BASE_CONFIG = "bandit.yaml"
LOG = logging.getLogger()


def _init_logger(log_level=logging.INFO, log_format=None):
    """Initialize the logger.

    :param debug: Whether to enable debug mode
    :return: An instantiated logging instance
    """
    LOG.handlers = []

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
            for root, _, filenames in os.walk(t):
                for filename in fnmatch.filter(filenames, ".bandit"):
                    bandit_files.append(os.path.join(root, filename))

        if len(bandit_files) > 1:
            LOG.error(
                "Multiple .bandit files found - scan separately or "
                "choose one with --ini\n\t%s",
                ", ".join(bandit_files),
            )
            sys.exit(2)

        elif len(bandit_files) == 1:
            ini_file = bandit_files[0]
            LOG.info("Found project level .bandit file: %s", bandit_files[0])

    if ini_file:
        return utils.parse_ini_file(ini_file)
    else:
        return None


def _init_extensions():
    from bandit.core import extension_loader as ext_loader

    return ext_loader.MANAGER


def _log_option_source(default_val, arg_val, ini_val, option_name):
    """It's useful to show the source of each option."""
    # When default value is not defined, arg_val and ini_val is deterministic
    if default_val is MISSING_NONPROP:
        if arg_val:
            LOG.info("Using command line arg for %s", option_name)
            return arg_val
        elif ini_val:
            LOG.info("Using ini file for %s", option_name)
            return ini_val
        else:
            return None
    # No value passed to commad line and default value is used
    elif default_val == arg_val:
        return ini_val if ini_val else arg_val
    # Certainly a value is passed to commad line
    else:
        return arg_val


def _running_under_virtualenv():
    if hasattr(sys, "real_prefix"):
        return True
    elif sys.prefix != getattr(sys, "base_prefix", sys.prefix):
        return True


def _get_profile(config, profile_name, config_path):
    profile = {}
    if profile_name:
        profiles = config.get_option("profiles") or {}
        profile = profiles.get(profile_name)
        if profile is None:
            raise utils.ProfileNotFound(config_path, profile_name)
        LOG.debug("read in legacy profile '%s': %s", profile_name, profile)
    else:
        profile["include"] = set(config.get_option("tests") or [])
        profile["exclude"] = set(config.get_option("skips") or [])
    return profile


def _log_info(args, profile):
    inc = ",".join([t for t in profile["include"]]) or "None"
    exc = ",".join([t for t in profile["exclude"]]) or "None"
    LOG.info("profile include tests: %s", inc)
    LOG.info("profile exclude tests: %s", exc)
    LOG.info("cli include tests: %s", args.tests)
    LOG.info("cli exclude tests: %s", args.skips)


def main():
    """Bandit CLI."""
    # bring our logging stuff up as early as possible
    debug = (
        logging.DEBUG
        if "-d" in sys.argv or "--debug" in sys.argv
        else logging.INFO
    )
    _init_logger(debug)
    extension_mgr = _init_extensions()

    baseline_formatters = [
        f.name
        for f in filter(
            lambda x: hasattr(x.plugin, "_accepts_baseline"),
            extension_mgr.formatters,
        )
    ]

    # now do normal startup
    plugin_info = [
        f"{a[0]}\t{a[1].name}" for a in extension_mgr.plugins_by_id.items()
    ]
    blacklist_info = []
    for a in extension_mgr.blacklist.items():
        for b in a[1]:
            blacklist_info.append(f"{b['id']}\t{b['name']}")

    plugin_list = "\n\t".join(sorted(set(plugin_info + blacklist_info)))
    dedent_text = textwrap.dedent(
        """
    CUSTOM FORMATTING
    -----------------

    Available tags:

        {abspath}, {relpath}, {line}, {col}, {test_id},
        {severity}, {msg}, {confidence}, {range}

    Example usage:

        Default template:
        bandit -r examples/ --format custom --msg-template \\
        "{abspath}:{line}: {test_id}[bandit]: {severity}: {msg}"

        Provides same output as:
        bandit -r examples/ --format custom

        Tags can also be formatted in python string.format() style:
        bandit -r examples/ --format custom --msg-template \\
        "{relpath:20.20s}: {line:03}: {test_id:^8}: DEFECT: {msg:>20}"

        See python documentation for more information about formatting style:
        https://docs.python.org/3/library/string.html

    The following tests were discovered and loaded:
    -----------------------------------------------
    """
    )

    # setup work - parse arguments, and initialize BanditManager
    version = f"%(prog)s {bandit.__version__}\n  python version = {sys.version.replace("\n", "")}"
    Env = get_env(extension_mgr)
    m = run(
        FlagCreatePairsOff[DisallowNone[Env]],
        ask_on_empty_cli=True,
        add_version=version,
        epilog=dedent_text + f"\t{plugin_list}",
    )
    args = m.env

    args.excluded_paths = ",".join(
        args.excluded_paths
    )  # NOTE for backwards compatibility where this was a str

    # Check if `--msg-template` is not present without custom formatter
    if args.format != "custom" and args.msg_template is not None:
        raise ValueError(
            "--msg-template can only be used with --format=custom"
        )

    # Check if confidence or severity level have been specified with strings
    if lev := args.severity_level:
        args.level = Level.get(lev).value

    if lev := args.confidence_level:
        args.confidence = Level.get(lev).value

    if not args.output:
        args.output = sys.stdout

    # Handle .bandit files in projects to pass cmdline args from file
    ini_options = _get_options_from_ini(args.ini_path, args.targets)
    if ini_options:
        # prefer command line, then ini file
        defaults = create_with_missing(Env, {})

        def _log(var, desc=None):
            return _log_option_source(
                getattr(defaults, var),
                getattr(args, var),
                ini_options.get(var.replace("_", "-")),
                desc or var,
            )

        ini_targets = ini_options.get("targets")
        if ini_targets:
            ini_targets = ini_targets.split(",")

        args.configfile = _log("configfile", "config file")
        args.excluded_paths = _log_option_source(
            ",".join(defaults.excluded_paths),
            args.excluded_paths,
            ini_options.get("exclude"),
            "excluded paths",
        )
        args.skips = _log("skips", "skipped tests")
        args.tests = _log("tests", "selected tests")
        args.targets = _log_option_source(
            defaults.targets,
            args.targets,
            ini_targets,
            "selected targets",
        )
        # TODO(tmcpeak): any other useful options to pass from .bandit?
        args.recursive = _log("recursive", "recursive scan")
        args.aggregate = _log("aggregate", "aggregate output type")
        args.context_lines = _log_option_source(
            defaults.context_lines,
            args.context_lines,
            int(ini_options.get("number") or 0) or None,
            "max code lines output for issue",
        )
        args.profile = _log("profile", "profile")
        args.level = _log("level", "severity level")
        args.confidence = _log("confidence", "confidence level")
        args.format = _log("format", "output format")
        args.msg_template = _log("msg_template", "output message template")
        args.output = _log("output", "output file")
        args.verbose = _log("verbose", "output extra information")
        args.debug = _log("debug", "debug mode")
        args.quiet = _log("quiet", "silent mode")
        args.ignore_nosec = _log(
            "ignore_nosec", "do not skip lines with # nosec"
        )
        args.baseline = _log("baseline", "path of a baseline report")

    try:
        b_conf = b_config.BanditConfig(config_file=args.configfile)
    except utils.ConfigError as e:
        LOG.error(e)
        sys.exit(2)

    # if the log format string was set in the options, reinitialize
    if b_conf.get_option("log_format"):
        log_format = b_conf.get_option("log_format")
        _init_logger(log_level=logging.DEBUG, log_format=log_format)

    if args.quiet:
        _init_logger(log_level=logging.WARN)

    try:
        profile = _get_profile(b_conf, args.profile, args.configfile)
        _log_info(args, profile)

        profile["include"].update(args.tests.split(",") if args.tests else [])
        profile["exclude"].update(args.skips.split(",") if args.skips else [])
        extension_mgr.validate_profile(profile)

    except (utils.ProfileNotFound, ValueError) as e:
        LOG.error(e)
        sys.exit(2)

    b_mgr = b_manager.BanditManager(
        b_conf,
        args.aggregate,
        args.debug,
        profile=profile,
        verbose=args.verbose,
        quiet=args.quiet,
        ignore_nosec=args.ignore_nosec,
    )

    if args.baseline is not None:
        try:
            with open(args.baseline) as bl:
                data = bl.read()
                b_mgr.populate_baseline(data)
        except OSError:
            LOG.warning("Could not open baseline report: %s", args.baseline)
            sys.exit(2)

        if args.format not in baseline_formatters:
            LOG.warning(
                "Baseline must be used with one of the following "
                "formats: " + str(baseline_formatters)
            )
            sys.exit(2)

    if args.format != "json":
        if args.configfile:
            LOG.info("using config: %s", args.configfile)

        LOG.info(
            "running on Python %d.%d.%d",
            sys.version_info.major,
            sys.version_info.minor,
            sys.version_info.micro,
        )

    # initiate file discovery step within Bandit Manager
    b_mgr.discover_files(args.targets, args.recursive, args.excluded_paths)

    if not b_mgr.b_ts.tests:
        LOG.error("No tests would be run, please check the profile.")
        sys.exit(2)

    # initiate execution of tests within Bandit Manager
    b_mgr.run_tests()
    LOG.debug(b_mgr.b_ma)
    LOG.debug(b_mgr.metrics)

    # trigger output of results by Bandit Manager
    sev_level = constants.RANKING[args.level - 1]
    conf_level = constants.RANKING[args.confidence - 1]
    b_mgr.output_results(
        args.context_lines,
        sev_level,
        conf_level,
        args.output,
        args.format,
        args.msg_template,
    )

    if (
        b_mgr.results_count(sev_filter=sev_level, conf_filter=conf_level) > 0
        and not args.exit_zero
    ):
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
