.. image:: https://github.com/PyCQA/bandit/blob/master/logo/logotype-sm.png
    :alt: Bandit

======

.. image:: https://github.com/PyCQA/bandit/workflows/Build%20and%20Test%20Bandit/badge.svg
    :target: https://github.com/PyCQA/bandit/actions?query=workflow%3A%22Build+and+Test+Bandit%22
    :alt: Build Status

.. image:: https://readthedocs.org/projects/bandit/badge/?version=latest
    :target: https://readthedocs.org/projects/bandit/
    :alt: Docs Status

.. image:: https://img.shields.io/pypi/v/bandit.svg
    :target: https://pypi.org/project/bandit/
    :alt: Latest Version

.. image:: https://img.shields.io/pypi/pyversions/bandit.svg
    :target: https://pypi.org/project/bandit/
    :alt: Python Versions

.. image:: https://img.shields.io/pypi/format/bandit.svg
    :target: https://pypi.org/project/bandit/
    :alt: Format

.. image:: https://img.shields.io/badge/license-Apache%202-blue.svg
    :target: https://github.com/PyCQA/bandit/blob/master/LICENSE
    :alt: License

A security linter from PyCQA

* Free software: Apache license
* Documentation: https://bandit.readthedocs.io/en/latest/
* Source: https://github.com/PyCQA/bandit
* Bugs: https://github.com/PyCQA/bandit/issues
* Contributing: https://github.com/PyCQA/bandit/blob/master/CONTRIBUTING.md

Overview
--------
Bandit is a tool designed to find common security issues in Python code. To do
this Bandit processes each file, builds an AST from it, and runs appropriate
plugins against the AST nodes. Once Bandit has finished scanning all the files
it generates a report.

Bandit was originally developed within the OpenStack Security Project and
later rehomed to PyCQA.

Installation
------------
Bandit is distributed on PyPI. The best way to install it is with pip:


Create a virtual environment (optional)::

    virtualenv bandit-env
    python3 -m venv bandit-env
    # And activate it:
    source bandit-env/bin/activate

Install Bandit::

    pip install bandit
    pip3 install bandit

Run Bandit::

    bandit -r path/to/your/code


Bandit can also be installed from source. To do so, download the source tarball
from PyPI, then install it::

    python setup.py install


Usage
-----
Example usage across a code tree::

    bandit -r ~/your_repos/project

Example usage across the ``examples/`` directory, showing three lines of
context and only reporting on the high-severity issues::

    bandit examples/*.py -n 3 -lll

Bandit can be run with profiles. To run Bandit against the examples directory
using only the plugins listed in the ``ShellInjection`` profile::

    bandit examples/*.py -p ShellInjection

Bandit also supports passing lines of code to scan using standard input. To
run Bandit with standard input::

    cat examples/imports.py | bandit -

For more usage information::

    bandit -h


Baseline
--------
Bandit allows specifying the path of a baseline report to compare against using the base line argument (i.e. ``-b BASELINE`` or ``--baseline BASELINE``).

::

   bandit -b BASELINE

This is useful for ignoring known vulnerabilities that you believe are non-issues (e.g. a cleartext password in a unit test). To generate a baseline report simply run Bandit with the output format set to ``json`` (only JSON-formatted files are accepted as a baseline) and output file path specified:

::

    bandit -f json -o PATH_TO_OUTPUT_FILE


Version control integration
---------------------------

Use `pre-commit <https://pre-commit.com/>`_. Once you `have it
installed <https://pre-commit.com/#install>`_, add this to the
`.pre-commit-config.yaml` in your repository
(be sure to update `rev` to point to a real git tag/revision!)::

    repos:
    -   repo: https://github.com/PyCQA/bandit
        rev: '' # Update me!
        hooks:
        - id: bandit


Then run `pre-commit install` and you're ready to go.

Configuration
-------------
An optional config file may be supplied and may include:
 - lists of tests which should or shouldn't be run
 - exclude_dirs - sections of the path, that if matched, will be excluded from
   scanning (glob patterns supported)
 - overridden plugin settings - may provide different settings for some
   plugins

Per Project Command Line Args
-----------------------------
Projects may include a `.bandit` file that specifies command line arguments
that should be supplied for that project. The currently supported arguments
are:

 - targets: comma separated list of target dirs/files to run bandit on
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

Test results are managed in the ``Manager`` and aggregated for
output at the completion of a test run through the method `output_result` from ``Manager`` instance.


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

Formatters need to accept 5 things:

- `manager`: an instance of `bandit manager`
- `fileobj`: the output file object, which may be sys.stdout
- `sev_level` : Filtering severity level
- `conf_level`: Filtering confidence level
- `lines=-1`: number of lines to report

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
Follow our Contributing file:
https://github.com/PyCQA/bandit/blob/master/CONTRIBUTING.md

Reporting Bugs
--------------
Bugs should be reported on github. To file a bug against Bandit, visit:
https://github.com/PyCQA/bandit/issues

Show Your Style
---------------
.. image:: https://img.shields.io/badge/security-bandit-yellow.svg
    :target: https://github.com/PyCQA/bandit
    :alt: Security Status

Use our badge in your project's README!

using Markdown::

    [![security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)

using RST::

    .. image:: https://img.shields.io/badge/security-bandit-yellow.svg
        :target: https://github.com/PyCQA/bandit
        :alt: Security Status

Under Which Version of Python Should I Install Bandit?
------------------------------------------------------
The answer to this question depends on the project(s) you will be running
Bandit against. If your project is only compatible with Python 3.5, you
should install Bandit to run under Python 3.5. If your project is only
compatible with Python 3.8, then use 3.8 respectively. If your project supports
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

Bandit docs: https://bandit.readthedocs.io/en/latest/

Python AST module documentation: https://docs.python.org/3/library/ast.html

Green Tree Snakes - the missing Python AST docs:
https://greentreesnakes.readthedocs.org/en/latest/

Documentation of the various types of AST nodes that Bandit currently covers
or could be extended to cover:
https://greentreesnakes.readthedocs.org/en/latest/nodes.html
