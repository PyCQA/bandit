Bandit
======

A security linter from OpenStack Security


Overview
--------
Bandit is a tool designed to find common security issues in Python code. To do
this Bandit processes each file, builds an AST from it, and runs appropriate
plugins against the AST nodes.  Once Bandit has finished scanning all the files
it generates a report.

Installation
------------
Bandit is distributed on PyPI.  The best way to install it is with pip:


***Create a virtual environment (optional):***

    virtualenv bandit-env

***Install Bandit:***

    pip install bandit

***Run Bandit:***

    bandit -r path/to/your/code


Bandit can also be installed from source.  To do so, download the source
tarball from PyPI, then install it:

    python setup.py install


Usage
-----
Example usage across a code tree:

    bandit -r ~/openstack-repo/keystone

Example usage across the examples/ directory, showing three lines of context
and only reporting on the high-severity issues:

    bandit examples/*.py -n 3 -lll

Bandit can be run with profiles.  To run Bandit against the examples directory
using only the plugins listed in the ShellInjection profile:

    bandit examples/*.py -p ShellInjection

Usage::

    bandit -h
    usage: bandit [-h] [-a AGG_TYPE] [-n CONTEXT_LINES] [-c CONFIG_FILE]
                  [-p PROFILE] [-l] [-o OUTPUT_FILE] [-d]
                  file [file ...]

    Bandit - a Python source code analyzer.

    positional arguments:
      file                  source file/s or directory to be tested

    optional arguments:
      -h, --help            show this help message and exit
      -r, --recursive       process files in subdirectories
      -a AGG_TYPE, --aggregate AGG_TYPE
                            group results by (vuln)erability type or (file) it
                            occurs in
      -n CONTEXT_LINES, --number CONTEXT_LINES
                            number of context lines to print
      -c CONFIG_FILE, --configfile CONFIG_FILE
                            test config file (default: bandit.yaml)
      -p PROFILE, --profile PROFILE
                            test set profile in config to use (defaults to all
                            tests)
      -l, --level           results level filter
      -f {txt,json}, --format {txt,json}
                            output format for STDOUT or file
      -o OUTPUT_FILE, --output OUTPUT_FILE
                            write report to filename
      -d, --debug           turn on debug mode


Configuration
-------------
The Bandit config file is used to set several things, including:
 - profiles - defines group of tests which should or shouldn't be run
 - exclude_dirs - sections of the path, that if matched, will be excluded from
 scanning
 - plugin configs - used to tune plugins, for example: by tuning
 blacklist_imports, you can set which imports should be flagged
 - other - plugins directory, included file types, shell display
 colors, etc.

Bandit requires a config file.  Bandit will use bandit.yaml in the following
preference order:

 - Bandit config file specified with -c command line option
 - bandit.yaml file from current working directory
 - bandit.yaml file from ~/.config/bandit/
 - bandit.yaml file in config/ directory of the Bandit package


Exclusions
----------
In the event that a line of code triggers a Bandit issue, but that the line
has been reviewed and the issue is a false positive or acceptable for some
other reason, the line can be marked with a '# nosec' and any results
associated with it will not be reported.

For example, although this line may cause Bandit to report a potential
security issue, it will not be reported::

    self.process = subprocess.Popen('/bin/echo', shell=True)  # nosec


Vulnerability Tests
-------------------
Vulnerability tests or 'plugins' are defined in files in the plugins directory.

Tests are written in Python and are autodiscovered from the plugins directory.
Each test can examine one or more type of Python statements.  Tests are marked
with the types of Python statements they examine (for example: function call,
string, import, etc).

Tests are executed by the BanditNodeVisitor object as it visits each node in
the AST.

Test results are maintained in the BanditResultStore and aggregated for output
at the completion of a test run.


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


Contributing
------------
Contributions to Bandit are always welcome!  We can be found on #openstack-security
on Freenode IRC.

The best way to get started with Bandit is to grab the source:

    git clone https://git.openstack.org/stackforge/bandit.git

You can test any changes with tox:

    pip install tox
    tox -e pep8
    tox -e py27
    tox -e cover


References
==========

Bandit wiki: https://wiki.openstack.org/wiki/Security/Projects/Bandit

Python AST module documentation: https://docs.python.org/2/library/ast.html

Green Tree Snakes - the missing Python AST docs:
http://greentreesnakes.readthedocs.org/en/latest/

Documentation of the various types of AST nodes that Bandit currently covers
or could be extended to cover:
http://greentreesnakes.readthedocs.org/en/latest/nodes.html
