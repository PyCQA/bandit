
start_process_with_partial_path
===============================

Description
-----------
Python possesses many mechanisms to invoke an external executable. If the
desired executable path is not fully qualified relative to the filesystem root
then this may present a potential security risk.

In POSIX environments, the `PATH` environment variable is used to specify a
set of standard locations that will be searched for the first matching named
executable. While convenient, this behavior may allow a malicious actor to
exert control over a system. If they are able to adjust the contents of the
`PATH` variable, or manipulate the file system, then a bogus executable may be
discovered in place of the desired one. This executable will be invoked with the
user privileges of the Python process that spawned it, potentially a highly
privileged user.

This test will scan the parameters of all configured Python methods, looking
for paths that do not start at the filesystem root, that is, do not have a
leading '/' character.

Available Since
---------------
 - Bandit v0.13.0

Config Options
--------------
This plugin test shares a configuration with others in the same family, namely
`shell_injection`. This configuration is divided up into three sections,
`subprocess`, `shell` and `no_shell`. They each list Python calls that spawn
subprocesses, invoke commands within a shell, or invoke commands without a
shell (by replacing the calling process) respectively.

This test will scan parameters of all methods in all sections. Note that methods
are fully qualified and de-aliased prior to checking.

.. code-block:: yaml

    shell_injection:
        # Start a process using the subprocess module, or one of its wrappers.
        subprocess:
            - subprocess.Popen
            - subprocess.call

        # Start a process with a function vulnerable to shell injection.
        shell:
            - os.system
            - os.popen
            - popen2.Popen3
            - popen2.Popen4
            - commands.getoutput
            - commands.getstatusoutput
        # Start a process with a function that is not vulnerable to shell injection.
        no_shell:
            - os.execl
            - os.execle


Sample Output
-------------
.. code-block:: none

    >> Issue: Starting a process with a partial executable path
    Severity: Low   Confidence: High
    Location: ./examples/partial_path_process.py:3
    2    from subprocess import Popen as pop
    3    pop('gcc --version', shell=False)

References
----------
- https://security.openstack.org
- https://docs.python.org/2/library/os.html#process-management
