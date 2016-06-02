======
bandit
======

SYNOPSIS
========

bandit [-h] [-r] [-a {file,vuln}] [-n CONTEXT_LINES] [-c CONFIG_FILE]
            [-p PROFILE] [-t TESTS] [-s SKIPS] [-l] [-i]
            [-f {csv,html,json,screen,txt,xml}] [-o OUTPUT_FILE] [-v] [-d]
            [--ignore-nosec] [-x EXCLUDED_PATHS] [-b BASELINE]
            [--ini INI_PATH] [--version]
            targets [targets ...]

DESCRIPTION
===========

``bandit`` is a tool designed to find common security issues in Python code. To
do this Bandit processes each file, builds an AST from it, and runs appropriate
plugins against the AST nodes.  Once Bandit has finished scanning all the files
it generates a report.

OPTIONS
=======

  -h, --help            show this help message and exit
  -r, --recursive       find and process files in subdirectories
  -a {file,vuln}, --aggregate {file,vuln}
                        aggregate output by vulnerability (default) or by
                        filename
  -n CONTEXT_LINES, --number CONTEXT_LINES
                        maximum number of code lines to output for each issue
  -c CONFIG_FILE, --configfile CONFIG_FILE
                        optional config file to use for selecting plugins and
                        overriding defaults
  -p PROFILE, --profile PROFILE
                        profile to use (defaults to executing all tests)
  -t TESTS, --tests TESTS
                        comma-separated list of test IDs to run
  -s SKIPS, --skip SKIPS
                        comma-separated list of test IDs to skip
  -l, --level           report only issues of a given severity level or higher
                        (-l for LOW, -ll for MEDIUM, -lll for HIGH)
  -i, --confidence      report only issues of a given confidence level or
                        higher (-i for LOW, -ii for MEDIUM, -iii for HIGH)
  -f {csv,html,json,screen,txt,xml}, --format {csv,html,json,screen,txt,xml}
                        specify output format
  -o OUTPUT_FILE, --output OUTPUT_FILE
                        write report to filename
  -v, --verbose         output extra information like excluded and included
                        files
  -d, --debug           turn on debug mode
  --ignore-nosec        do not skip lines with # nosec comments
  -x EXCLUDED_PATHS, --exclude EXCLUDED_PATHS
                        comma-separated list of paths to exclude from scan
                        (note that these are in addition to the excluded paths
                        provided in the config file)
  -b BASELINE, --baseline BASELINE
                        path of a baseline report to compare against (only
                        JSON-formatted files are accepted)
  --ini INI_PATH        path to a .bandit file that supplies command line
                        arguments
  --version             show program's version number and exit

FILES
=====

.bandit
  file that supplies command line arguments

/etc/bandit/bandit.yaml
  legacy bandit configuration file

EXAMPLES
========

Example usage across a code tree::

    bandit -r ~/openstack-repo/keystone

Example usage across the ``examples/`` directory, showing three lines of
context and only reporting on the high-severity issues::

    bandit examples/*.py -n 3 -lll

Bandit can be run with profiles.  To run Bandit against the examples directory
using only the plugins listed in the ShellInjection profile::

    bandit examples/*.py -p ShellInjection

SEE ALSO
========

pylint(1)
