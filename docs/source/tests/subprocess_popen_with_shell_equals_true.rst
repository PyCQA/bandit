
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
this type are identified by a parameter of "shell=True" being given.

Additionally, this plugin scans the command string given and adjusts its
reported severity based on how it is presented. If the command string is a
simple static string containing no special shell characters, then the resulting
issue has low severity. If the string is static, but contains shell formatting
characters or wildcards, then the reported issue is medium. Finally, if the
string is computed using Python's string manipulation or formatting operations,
then the reported issue has high severity. These severity levels reflect the
likelihood that the code is vulnerable to injection.

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

    >> Issue: subprocess call with shell=True seems safe, but may be changed in
    the future, consider rewriting without shell
       Severity: Low   Confidence: High
       Location: ./examples/subprocess_shell.py:21
    20	subprocess.check_call(['/bin/ls', '-l'], shell=False)
    21	subprocess.check_call('/bin/ls -l', shell=True)
    22

    >> Issue: call with shell=True contains special shell characters, consider
    moving extra logic into Python code
       Severity: Medium   Confidence: High
       Location: ./examples/subprocess_shell.py:26
    25
    26	subprocess.Popen('/bin/ls *', shell=True)
    27	subprocess.Popen('/bin/ls %s' % ('something',), shell=True)

    >> Issue: subprocess call with shell=True identified, security issue.
       Severity: High   Confidence: High
       Location: ./examples/subprocess_shell.py:27
    26	subprocess.Popen('/bin/ls *', shell=True)
    27	subprocess.Popen('/bin/ls %s' % ('something',), shell=True)
    28	subprocess.Popen('/bin/ls {}'.format('something'), shell=True)

References
----------
- https://security.openstack.org
- https://docs.python.org/2/library/subprocess.html#frequently-used-arguments
- https://security.openstack.org/guidelines/dg_use-subprocess-securely.html
- https://security.openstack.org/guidelines/dg_avoid-shell-true.html
