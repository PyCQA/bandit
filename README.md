Bandit
======

A Python AST-based static analyzer from OpenStack Security Group.


Overview
--------
Bandit provides a framework for performing analysis against Python source code,
utilizing the ast module from the Python standard library.

The ast module is used to convert source code into a parsed tree of Python
syntax nodes.  Bandit allows users to define custom tests that are performed
against those nodes.  At the completion of testing, a report is generated that
lists security issues identified within the target source code.


Usage
-----
Example usage across a code tree, showing one line of context for each issue:

    find ~/openstack-repo/keystone -name '*.py' | xargs ./main.py -C 1


Example usage across the examples/ directory, showing three lines of context
and only reporting on the high-severity issues:

    ./main.py examples/*.py -C 3 -lll


Usage:

    $ ./main.py -h
    usage: main.py [-h] [-C CONTEXT_LINES] [-t TEST_CONFIG] [-l] [-o OUTPUT_FILE]
                   [-d] file [file ...]

    Bandit - a Python source code analyzer.

    positional arguments:
      file                  source file/s to be tested

    optional arguments:
      -h, --help            show this help message and exit
      -C CONTEXT_LINES, --context CONTEXT_LINES
                            number of context lines to print
      -f CONFIG_FILE, --configfile TEST_CONFIG
                            test config file (default: bandit.yaml)
      -p PROFILE_NAME, --profile PROFILE_NAME
                            run using specified test profile
      -l, --level           results level filter
      -o OUTPUT_FILE, --output OUTPUT_FILE
                            write report to filename
      -d, --debug           turn on debug mode



Exclusions
----------
In the event that a line of code triggers a Bandit issue, but that the line
has been reviewed and the issue is a false positive or acceptable for some
other reason, the line can be marked with a '# nosec' and any results
associated with it will not be reported.

For example, although this line may cause Bandit to report a potential
security issue, it will not be reported:

    self.process = subprocess.Popen('/bin/echo', shell=True)  # nosec


Vulnerability Tests
------------------
Vulnerability tests are currently defined in files in the plugins/ directory.

Tests are associated with AST node types based on Bandit configuration file
(bandit.ini), and loaded at run time.

Tests are executed by the BanditNodeVisitor object as it visits each node in
the AST.  

Test results are maintained in the BanditResultStore and aggregated for output
at the completion of a test run.


Writing Tests
-------------
To write a test:
 - Identify a vulnerability to build a test for, and create a new file in
   examples/ that contains one or more cases of that vulnerability.
 - Consider the vulnerability you're testing for, and identify the AST node
   type that might best be used to detect that vulnerability.
 - Check that the Bandit framework already has a node visitor defined for that
   node type.  Look at bandit/node\_visitor.py and check that a
   visit\_[typename] function is defined.
 - Add a new function to the relevant plugins/test\_\*.py file, that conducts
   the relevant test and returns an appropriate result.  Review existing tests
   for examples of what this looks like.
 - Modify bandit.ini to include the new function in tests targeting the node
   type in question.
 - Execute Bandit against the test file you defined in examples/ and ensure
   that it detects the vulnerability.  Consider variations on how this
   vulnerability might present itself and extend the example file and the test
   function accordingly.

The BanditNodeVisitor object provides a 'context' object that the test
function can refer to as part of the testing being performed.  Tests should
most likely examine the AST node directly, accessible through context['node'].

See links in the 'References' section for documentation of each AST node type.


References
==========

Python AST module documentation: https://docs.python.org/2/library/ast.html

Green Tree Snakes - the missing Python AST docs:
http://greentreesnakes.readthedocs.org/en/latest/

Of specific node, the various types of AST nodes that Bandit currently covers
or could be extended to cover:
http://greentreesnakes.readthedocs.org/en/latest/nodes.html


