any_other_function_with_shell_equals_true
=========================================

Description
-----------
This plugin test interrogates method calls for the presence of a keyword
parameter `shell` equalling true. It is related to detection of shell injection
issues and is intended to catch custom wrappers to vulnerable methods that may
have been created.

Available Since
---------------
 - Bandit v 0.9.0

Config Options
--------------
This plugin method takes a configuration block shared with various related
plugins. The config block `shell_injection` is provided to list various
classes of function call that are considered by this and other plugins relating
to detection of shell injection issues.

Specifically, this plugin excludes those functions listed under the subprocess
section, these methods are tested in a separate specific test plugin and this
exclusion prevents duplicate issue reporting.

.. code-block:: yaml

    shell_injection:
        # Start a process using the subprocess module, or one of its wrappers.
        subprocess: [subprocess.Popen, subprocess.call, subprocess.check_call,
                     subprocess.check_output, utils.execute,
                     utils.execute_with_timeout]


Sample Output
-------------
.. code-block:: none

    >> Issue: Function call with shell=True parameter identifed, possible security issue.
       Severity: Medium   Confidence: High
       Location: ./examples/subprocess_shell.py:9
    8 pop('/bin/gcc --version', shell=True)
    9 Popen('/bin/gcc --version', shell=True)
    10

References
----------
 - https://security.openstack.org/guidelines/dg_avoid-shell-true.html
 - https://security.openstack.org/guidelines/dg_use-subprocess-securely.html
