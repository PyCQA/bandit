
subprocess_popen_with_shell_equals_true
=======================================

Description
-----------
Python possesses many mechanisms to invoke an external executable. However,
doing so may present a security issue if appropriate care is not taken to
sanitize any user provided or variable input.

This plugin test is part of a family of tests built to check for process
spawning and warn appropriately. Specifically, this test looks for the spawning
of a subprocess using a command shell. This type of subprocess invocation is
dangerous as it is vulnerable to various shell injection attacks. Great care
should be taken to sanitize all input in order to mitigate this risk. Calls of
this type are identified by a parameter of "shell=True" being given in addition
to the command to run, Bandit will report a HIGH severity warning.

See also:

- :doc:`linux_commands_wildcard_injection`.
- :doc:`subprocess_without_shell_equals_true`.
- :doc:`start_process_with_no_shell`.
- :doc:`start_process_with_a_shell`.
- :doc:`start_process_with_partial_path`.

Available Since
---------------
 - Bandit v0.9.0

Config Options
--------------
This plugin test shares a configuration with others in the same family, namely
`shell_injection`. This configuration is divided up into three sections,
`subprocess`, `shell` and `no_shell`. They each list Python calls that spawn
subprocesses, invoke commands within a shell, or invoke commands without a
shell (by replacing the calling process) respectively.

This plugin specifically scans for methods listed in `subprocess` section that
have shell=True specified.

.. code-block:: yaml

    shell_injection:

        # Start a process using the subprocess module, or one of its wrappers.
        subprocess:
            - subprocess.Popen
            - subprocess.call


Sample Output
-------------
.. code-block:: none

    >> Issue: subprocess call with shell=True identified, security issue.
       Severity: High   Confidence: High
       Location: ./examples/subprocess_shell.py:24
    23  subprocess.check_output(['/bin/ls', '-l'])
    24  subprocess.check_output('/bin/ls -l', shell=True)
    25

References
----------
- https://security.openstack.org
- https://docs.python.org/2/library/subprocess.html#frequently-used-arguments
- https://security.openstack.org/guidelines/dg_use-subprocess-securely.html
