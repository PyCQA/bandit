
execute_with_run_as_root_equals_true
====================================

Description
-----------
Running commands as root dramatically increase their potential risk. Running
commands with restricted user privileges provides defense in depth against
command injection attacks, or developer and configuration error. This plugin
test checks for specific methods being called with a keyword parameter
`run_as_root` set to True, a common OpenStack idiom.


Available Since
---------------
 - Bandit v0.10.0

Config Options
--------------
This test plugin takes a similarly named configuration block,
`execute_with_run_as_root_equals_true`, providing a list, `function_names`, of
function names. A call to any of these named functions will be checked for a
`run_as_root` keyword parameter, and if True, will report a Low severity
issue.

.. code-block:: yaml

    execute_with_run_as_root_equals_true:
        function_names:
            - ceilometer.utils.execute
            - cinder.utils.execute
            - neutron.agent.linux.utils.execute
            - nova.utils.execute
            - nova.utils.trycmd


Sample Output
-------------
.. code-block:: none

    >> Issue: Execute with run_as_root=True identified, possible security issue.
       Severity: Low   Confidence: Medium
       Location: ./examples/exec-as-root.py:26
    25  nova_utils.trycmd('gcc --version')
    26  nova_utils.trycmd('gcc --version', run_as_root=True)
    27

References
----------
 - https://security.openstack.org/guidelines/dg_rootwrap-recommendations-and-plans.html
 - https://security.openstack.org/guidelines/dg_use-oslo-rootwrap-securely.html
