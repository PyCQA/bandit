Bandit
======

.. image:: https://governance.openstack.org/badges/bandit.svg
    :target: https://governance.openstack.org/reference/tags/index.html
    :alt: Bandit team and repository tags

.. image:: https://img.shields.io/pypi/v/bandit.svg
    :target: https://pypi.python.org/pypi/bandit/
    :alt: Latest Version

.. image:: https://img.shields.io/pypi/pyversions/bandit.svg
    :target: https://pypi.python.org/pypi/bandit/
    :alt: Python Versions

.. image:: https://img.shields.io/pypi/format/bandit.svg
    :target: https://pypi.python.org/pypi/bandit/
    :alt: Format

.. image:: https://img.shields.io/badge/license-Apache%202-blue.svg
    :target: https://git.openstack.org/cgit/openstack/bandit/plain/LICENSE
    :alt: License

A security linter from OpenStack Security

* Free software: Apache license
* Documentation: https://wiki.openstack.org/wiki/Security/Projects/Bandit
* Source: https://git.openstack.org/cgit/openstack/bandit
* Bugs: https://bugs.launchpad.net/bandit

Overview
--------
Bandit is a tool designed to find common security issues in Python code. To do
this Bandit processes each file, builds an AST from it, and runs appropriate
plugins against the AST nodes. Once Bandit has finished scanning all the files
it generates a report.

Installation
------------
Bandit is distributed on PyPI. The best way to install it is with pip:


Create a virtual environment (optional)::

    virtualenv bandit-env

Install Bandit::

    pip install bandit
    # Or if you're working with a Python 3.5 project
    pip3.5 install bandit

Run Bandit::

    bandit -r path/to/your/code


Bandit can also be installed from source. To do so, download the source tarball
from PyPI, then install it::

    python setup.py install


Usage
-----
Example usage across a code tree::

    bandit -r ~/openstack-repo/keystone

Example usage across the ``examples/`` directory, showing three lines of
context and only reporting on the high-severity issues::

    bandit examples/*.py -n 3 -lll

Bandit can be run with profiles. To run Bandit against the examples directory
using only the plugins listed in the ``ShellInjection`` profile::

    bandit examples/*.py -p ShellInjection

Bandit also supports passing lines of code to scan using standard input. To
run Bandit with standard input::

    cat examples/imports.py | bandit -

Usage::

    $ bandit -h
    usage: bandit [-h] [-r] [-a {file,vuln}] [-n CONTEXT_LINES] [-c CONFIG_FILE]
                  [-p PROFILE] [-t TESTS] [-s SKIPS] [-l] [-i]
                  [-f {csv,html,json,screen,txt,xml,yaml}] [-o [OUTPUT_FILE]] [-v]
                  [-d] [--ignore-nosec] [-x EXCLUDED_PATHS] [-b BASELINE]
                  [--ini INI_PATH] [--version]
                  targets [targets ...]

    Bandit - a Python source code security analyzer

    positional arguments:
      targets               source file(s) or directory(s) to be tested

    optional arguments:
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
      -f {csv,html,json,screen,txt,xml,yaml}, --format {csv,html,json,screen,txt,xml,yaml}
                            specify output format
      -o [OUTPUT_FILE], --output [OUTPUT_FILE]
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

    The following tests were discovered and loaded:
      B101  assert_used
      B102  exec_used
      B103  set_bad_file_permissions
      B104  hardcoded_bind_all_interfaces
      B105  hardcoded_password_string
      B106  hardcoded_password_funcarg
      B107  hardcoded_password_default
      B108  hardcoded_tmp_directory
      B109  password_config_option_not_marked_secret
      B110  try_except_pass
      B111  execute_with_run_as_root_equals_true
      B112  try_except_continue
      B201  flask_debug_true
      B301  pickle
      B302  marshal
      B303  md5
      B304  ciphers
      B305  cipher_modes
      B306  mktemp_q
      B307  eval
      B308  mark_safe
      B309  httpsconnection
      B310  urllib_urlopen
      B311  random
      B312  telnetlib
      B313  xml_bad_cElementTree
      B314  xml_bad_ElementTree
      B315  xml_bad_expatreader
      B316  xml_bad_expatbuilder
      B317  xml_bad_sax
      B318  xml_bad_minidom
      B319  xml_bad_pulldom
      B320  xml_bad_etree
      B321  ftplib
      B322  input
      B323  unverified_context
      B401  import_telnetlib
      B402  import_ftplib
      B403  import_pickle
      B404  import_subprocess
      B405  import_xml_etree
      B406  import_xml_sax
      B407  import_xml_expat
      B408  import_xml_minidom
      B409  import_xml_pulldom
      B410  import_lxml
      B411  import_xmlrpclib
      B412  import_httpoxy
      B501  request_with_no_cert_validation
      B502  ssl_with_bad_version
      B503  ssl_with_bad_defaults
      B504  ssl_with_no_version
      B505  weak_cryptographic_key
      B506  yaml_load
      B601  paramiko_calls
      B602  subprocess_popen_with_shell_equals_true
      B603  subprocess_without_shell_equals_true
      B604  any_other_function_with_shell_equals_true
      B605  start_process_with_a_shell
      B606  start_process_with_no_shell
      B607  start_process_with_partial_path
      B608  hardcoded_sql_expressions
      B609  linux_commands_wildcard_injection
      B701  jinja2_autoescape_false
      B702  use_of_mako_templates


Configuration
-------------
An optional config file may be supplied and may include:
 - lists of tests which should or shouldn't be run
 - exclude_dirs - sections of the path, that if matched, will be excluded from
   scanning
 - overridden plugin settings - may provide different settings for some
   plugins

Per Project Command Line Args
-----------------------------
Projects may include a `.bandit` file that specifies command line arguments
that should be supplied for that project. The currently supported arguments
are:

 - exclude: comma separated list of excluded paths
 - skips: comma separated list of tests to skip
 - tests: comma separated list of tests to run

To use this, put a .bandit file in your project's directory. For example:

::

   [bandit]
   exclude: /test

::

   [bandit]
   tests: B101,B102,B301


Exclusions
----------
In the event that a line of code triggers a Bandit issue, but that the line
has been reviewed and the issue is a false positive or acceptable for some
other reason, the line can be marked with a ``# nosec`` and any results
associated with it will not be reported.

For example, although this line may cause Bandit to report a potential
security issue, it will not be reported::

    self.process = subprocess.Popen('/bin/echo', shell=True)  # nosec


Vulnerability Tests
-------------------
Vulnerability tests or "plugins" are defined in files in the plugins directory.

Tests are written in Python and are autodiscovered from the plugins directory.
Each test can examine one or more type of Python statements. Tests are marked
with the types of Python statements they examine (for example: function call,
string, import, etc).

Tests are executed by the ``BanditNodeVisitor`` object as it visits each node
in the AST.

Test results are maintained in the ``BanditResultStore`` and aggregated for
output at the completion of a test run.


Writing Tests
-------------
To write a test:
 - Identify a vulnerability to build a test for, and create a new file in
   examples/ that contains one or more cases of that vulnerability.
 - Consider the vulnerability you're testing for, mark the function with one
   or more of the appropriate decorators:
   - @checks('Call')
   - @checks('Import', 'ImportFrom')
   - @checks('Str')
 - Create a new Python source file to contain your test, you can reference
   existing tests for examples.
 - The function that you create should take a parameter "context" which is
   an instance of the context class you can query for information about the
   current element being examined.  You can also get the raw AST node for
   more advanced use cases.  Please see the context.py file for more.
 - Extend your Bandit configuration file as needed to support your new test.
 - Execute Bandit against the test file you defined in examples/ and ensure
   that it detects the vulnerability.  Consider variations on how this
   vulnerability might present itself and extend the example file and the test
   function accordingly.


Extending Bandit
----------------

Bandit allows users to write and register extensions for checks and formatters.
Bandit will load plugins from two entry-points:

- `bandit.formatters`
- `bandit.plugins`

Formatters need to accept 4 things:

- `result_store`: An instance of `bandit.core.BanditResultStore`
- `file_list`: The list of files which were inspected in the scope
- `scores`: The scores awarded to each file in the scope
- `excluded_files`: The list of files that were excluded from the scope

Plugins tend to take advantage of the `bandit.checks` decorator which allows
the author to register a check for a particular type of AST node. For example

::

    @bandit.checks('Call')
    def prohibit_unsafe_deserialization(context):
        if 'unsafe_load' in context.call_function_name_qual:
            return bandit.Issue(
                severity=bandit.HIGH,
                confidence=bandit.HIGH,
                text="Unsafe deserialization detected."
            )

To register your plugin, you have two options:

1. If you're using setuptools directly, add something like the following to
   your ``setup`` call::

        # If you have an imaginary bson formatter in the bandit_bson module
        # and a function called `formatter`.
        entry_points={'bandit.formatters': ['bson = bandit_bson:formatter']}
        # Or a check for using mako templates in bandit_mako that
        entry_points={'bandit.plugins': ['mako = bandit_mako']}

2. If you're using pbr, add something like the following to your `setup.cfg`
   file::

        [entry_points]
        bandit.formatters =
            bson = bandit_bson:formatter
        bandit.plugins =
            mako = bandit_mako

Contributing
------------
Contributions to Bandit are always welcome! We can be found on
#openstack-security on Freenode IRC.

The best way to get started with Bandit is to grab the source::

    git clone https://git.openstack.org/openstack/bandit.git

You can test any changes with tox::

    pip install tox
    tox -e pep8
    tox -e py27
    tox -e py35
    tox -e docs
    tox -e cover

Reporting Bugs
--------------
Bugs should be reported on Launchpad. To file a bug against Bandit, visit:
https://bugs.launchpad.net/bandit/+filebug

Under Which Version of Python Should I Install Bandit?
------------------------------------------------------
The answer to this question depends on the project(s) you will be running
Bandit against. If your project is only compatible with Python 2.7, you
should install Bandit to run under Python 2.7. If your project is only
compatible with Python 3.5, then use 3.5 respectively. If your project supports
both, you *could* run Bandit with both versions but you don't have to.

Bandit uses the `ast` module from Python's standard library in order to
analyze your Python code. The `ast` module is only able to parse Python code
that is valid in the version of the interpreter from which it is imported. In
other words, if you try to use Python 2.7's `ast` module to parse code written
for 3.5 that uses, for example, `yield from` with asyncio, then you'll have
syntax errors that will prevent Bandit from working properly. Alternatively,
if you are relying on 2.7's octal notation of `0777` then you'll have a syntax
error if you run Bandit on 3.x.


References
==========

Bandit wiki: https://wiki.openstack.org/wiki/Security/Projects/Bandit

Python AST module documentation: https://docs.python.org/2/library/ast.html

Green Tree Snakes - the missing Python AST docs:
https://greentreesnakes.readthedocs.org/en/latest/

Documentation of the various types of AST nodes that Bandit currently covers
or could be extended to cover:
https://greentreesnakes.readthedocs.org/en/latest/nodes.html
