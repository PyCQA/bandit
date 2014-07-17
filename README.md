Bandit
======

A Python AST-based static analyzer from OpenStack Security Group.

References
----------
Python AST module documentation: https://docs.python.org/2/library/ast.html

Green Tree Snakes - the missing Python AST docs:
http://greentreesnakes.readthedocs.org/en/latest/


Usage
-----
Example usage across a code tree:

    find ~/openstack-repo/keystone -name '*.py' | xargs ./main.py -C 1

Usage:

    $ ./main.py -h
    usage: main.py [-h] [-C CONTEXT_LINES] [-t TEST_CONFIG] [-l] [-d]
                   file [file ...]

    Bandit - a Python source code analyzer.

    positional arguments:
      file                  source file/s to be tested

    optional arguments:
      -h, --help            show this help message and exit
      -C CONTEXT_LINES, --context CONTEXT_LINES
                            number of context lines to print
      -t TEST_CONFIG, --testconfig TEST_CONFIG
                            test config file (default: bandit.ini)
      -l, --level           results level filter
      -d, --debug           turn on debug mode

