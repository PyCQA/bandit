
password_config_option_not_marked_secret
========================================

Description
-----------
Passwords are sensitive and must be protected appropriately.  In OpenStack
Oslo there is an option to mark options "secret" which will ensure that they
are not logged.  This plugin detects usages of oslo configuration functions
that appear to deal with strings ending in 'password' and flag usages where
they have not been marked secret.

If such a value is found a MEDIUM severity error is generated.  If 'False' or
'None' are explicitly set, Bandit will return a MEDIUM confidence issue.  If
Bandit can't determine the value of secret it will return a LOW confidence
issue.

Available Since
---------------
 - Bandit v0.10.0

Config Options
--------------
.. code-block:: yaml

    password_config_option_not_marked_secret:
        function_names:
            - oslo.config.cfg.StrOpt
            - oslo_config.cfg.StrOpt

Sample Output
-------------
.. code-block:: none

    >> Issue: [password_config_option_not_marked_secret] oslo config option
    possibly not marked secret=True identified.
       Severity: Medium   Confidence: Low
       Location: examples/secret-config-option.py:12
    11                  help="User's password"),
    12       cfg.StrOpt('nova_password',
    13                  secret=secret,
    14                  help="Nova user password"),
    15   ]

    >> Issue: [password_config_option_not_marked_secret] oslo config option not
    marked secret=True identifed, security issue.
       Severity: Medium   Confidence: Medium
       Location: examples/secret-config-option.py:21
    20                  help="LDAP ubind ser name"),
    21       cfg.StrOpt('ldap_password',
    22                  help="LDAP bind user password"),
    23       cfg.StrOpt('ldap_password_attribute',

References
----------
- https://security.openstack.org/guidelines/dg_protect-sensitive-data-in-files.html
- http://docs.openstack.org/developer/oslo.config/cfg.html#special-handling-instructions
