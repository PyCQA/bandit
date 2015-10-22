
ssl_with_bad_defaults
=====================

Description
-----------
Several highly publicized [1]_ [2]_, exploitable flaws have been discovered in
all versions of SSL and early versions of TLS. It is strongly recommended that
use of the following known broken protocol versions be avoided:

- SSL v2
- SSL v3
- TLS v1
- TLS v1.1

This plugin is part of a family of tests that detect the use of known bad
versions of SSL/TLS, please see :doc:`ssl_with_bad_version` for a complete
discussion. Specifically, this plugin test scans for Python methods with default
parameter values that specify the use of broken SSL/TLS protocol versions.
Currently, detection supports methods using Python's native SSL/TLS support and
the pyOpenSSL module. A MEDIUM severity warning will be reported whenever known
broken protocol versions are detected.

See also:

- :doc:`ssl_with_bad_version`.
- :doc:`ssl_with_no_version`.


Available Since
---------------
 - Bandit v0.9.0

Config Options
--------------
This test shares the configuration provided for the standard
:doc:`ssl_with_bad_version` test, please refer to it's
:ref:`bad_ssl_config_options` documentation.

Sample Output
-------------
.. code-block:: none

    >> Issue: Function definition identified with insecure SSL/TLS protocol
    version by default, possible security issue.
       Severity: Medium   Confidence: Medium
       Location: ./examples/ssl-insecure-version.py:28
    27
    28  def open_ssl_socket(version=SSL.SSLv2_METHOD):
    29      pass

References
----------
- [1] http://heartbleed.com/
- [2] https://poodlebleed.com/
- https://security.openstack.org/
- https://security.openstack.org/guidelines/dg_move-data-securely.html
