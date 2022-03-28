Configuration
=============

---------------
Bandit Settings
---------------

Projects may include a YAML file named `.bandit` that specifies command line
arguments that should be supplied for that project. The currently supported
arguments are:

 - targets: comma separated list of target dirs/files to run bandit on
 - exclude: comma separated list of excluded paths
 - skips: comma separated list of tests to skip
 - tests: comma separated list of tests to run

To use this, put a YAML file named `.bandit` in your project's directory.
For example:

::

   exclude: /test

::

   tests:
     - B101
     - B102
     - B301


Exclusions
----------
In the event that a line of code triggers a Bandit issue, but that the line
has been reviewed and the issue is a false positive or acceptable for some
other reason, the line can be marked with a ``# nosec`` and any results
associated with it will not be reported.

For example, although this line may cause Bandit to report a potential
security issue, it will not be reported::

    self.process = subprocess.Popen('/bin/echo', shell=True)  # nosec

Because multiple issues can be reported for the same line, specific tests may
be provided to suppress those reports. This will cause other issues not
included to be reported. This can be useful in preventing situations where a
nosec comment is used, but a separate vulnerability may be added to the line
later causing the new vulnerability to be ignored.

For example, this will suppress the report of B602 and B607::

    self.process = subprocess.Popen('/bin/ls *', shell=True)  #nosec B602, B607

Full test names rather than the test ID may also be used.

For example, this will suppress the report of B101 and continue to report B506
as an issue.::

    assert yaml.load("{}") == []  # nosec assert_used

-----------------
Scanning Behavior
-----------------

Bandit is designed to be configurable and cover a wide range of needs, it may
be used as either a local developer utility or as part of a full CI/CD
pipeline. To provide for these various usage scenarios bandit can be configured
via a `YAML <http://yaml.org/>`_ file. This file is completely optional and in
many cases not needed, it may be specified on the command line by using `-c`.

A bandit configuration file may choose the specific test plugins to run and
override the default configurations of those tests. An example config might
look like the following:

.. code-block:: yaml

  ### profile may optionally select or skip tests

  # (optional) list included tests here:
  tests: ['B201', 'B301']

  # (optional) list skipped tests here:
  skips: ['B101', 'B601']

  ### override settings - used to set settings for plugins to non-default values

  any_other_function_with_shell_equals_true:
    no_shell: [os.execl, os.execle, os.execlp, os.execlpe, os.execv, os.execve,
      os.execvp, os.execvpe, os.spawnl, os.spawnle, os.spawnlp, os.spawnlpe,
      os.spawnv, os.spawnve, os.spawnvp, os.spawnvpe, os.startfile]
    shell: [os.system, os.popen, os.popen2, os.popen3, os.popen4,
      popen2.popen2, popen2.popen3, popen2.popen4, popen2.Popen3,
      popen2.Popen4, commands.getoutput,  commands.getstatusoutput]
    subprocess: [subprocess.Popen, subprocess.call, subprocess.check_call,
      subprocess.check_output]

If you require several sets of tests for specific tasks, then you should create
several config files and pick from them using `-c`. If you only wish to control
the specific tests that are to be run (and not their parameters) then using
`-s` or `-t` on the command line may be more appropriate.

Also you can configure bandit via
`pyproject.toml <https://www.python.org/dev/peps/pep-0518/>`_ file. In this
case you would explicitly specify the path to configuration via `-c` too.
For example:

.. code-block:: TOML

  [tool.bandit]
  tests = ["B201", "B301"]
  skips = ["B101", "B601"]

  [tool.bandit.any_other_function_with_shell_equals_true]
  no_shell = [
    "os.execl",
    "os.execle",
    "os.execlp",
    "os.execlpe",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.execvpe",
    "os.spawnl",
    "os.spawnle",
    "os.spawnlp",
    "os.spawnlpe",
    "os.spawnv",
    "os.spawnve",
    "os.spawnvp",
    "os.spawnvpe",
    "os.startfile"
  ]
  shell = [
    "os.system",
    "os.popen",
    "os.popen2",
    "os.popen3",
    "os.popen4",
    "popen2.popen2",
    "popen2.popen3",
    "popen2.popen4",
    "popen2.Popen3",
    "popen2.Popen4",
    "commands.getoutput",
    "commands.getstatusoutput"
  ]
  subprocess = [
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output"
  ]


Skipping Tests
--------------
The bandit config may contain optional lists of test IDs to either include
(`tests`) or exclude (`skips`). These lists are equivalent to using `-t` and
`-s` on the command line. If only `tests` is given then bandit will include
only those tests, effectively excluding all other tests. If only `skips`
is given then bandit will include all tests not in the skips list. If both are
given then bandit will include only tests in `tests` and then remove `skips`
from that set. It is an error to include the same test ID in both `tests` and
`skips`.

Note that command line options `-t`/`-s` can still be used in conjunction with
`tests` and `skips` given in a config. The result is to concatenate `-t` with
`tests` and likewise for `-s` and `skips` before working out the tests to run.

Suppressing Individual Lines
----------------------------

If you have lines in your code triggering vulnerability errors and you are
certain that this is acceptable, they can be individually silenced by appending
``# nosec`` to the line::

    # The following hash is not used in any security context. It is only used
    # to generate unique values, collisions are acceptable and "data" is not
    # coming from user-generated input
    the_hash = md5(data).hexdigest()  # nosec


In such cases, it is good practice to add a comment explaining *why* a given
line was excluded from security checks.

Generating a Config
-------------------
Bandit ships the tool `bandit-config-generator` designed to take the leg work
out of configuration. This tool can generate a configuration file
automatically. The generated configuration will include default config blocks
for all detected test and blacklist plugins. This data can then be deleted or
edited as needed to produce a minimal config as desired. The config generator
supports `-t` and `-s` command line options to specify a list of test IDs that
should be included or excluded respectively. If no options are given then the
generated config will not include `tests` or `skips` sections (but will provide
a complete list of all test IDs for reference when editing).

Configuring Test Plugins
------------------------
Bandit's configuration file is written in `YAML <http://yaml.org/>`_ and options
for each plugin test are provided under a section named to match the test
method. For example, given a test plugin called 'try_except_pass' its
configuration section might look like the following:

.. code-block:: yaml

    try_except_pass:
      check_typed_exception: True

The specific content of the configuration block is determined by the plugin
test itself. See the `plugin test list <plugins/index.html>`_ for complete
information on configuring each one.
