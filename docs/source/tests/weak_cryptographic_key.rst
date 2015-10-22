
weak_cryptographic_key
======================

Description
-----------
As computational power increases, so does the ability to break ciphers with
smaller key lengths. The recommended key length size is 2048 and higher. 1024
bits and below are now considered breakable. This plugin test checks for use
of any key less than 2048 bits and returns a high severity error if lower than
1024 and a medium severity error greater than 1024 but less than 2048.

Available Since
---------------
 - Bandit v0.14.0

Config Options
--------------
None

Sample Output
-------------
.. code-block:: none

    >> Issue: DSA key sizes below 1024 bits are considered breakable.
       Severity: High   Confidence: High
       Location: examples/weak_cryptographic_key_sizes.py:36
    35  # Also incorrect: without keyword args
    36  dsa.generate_private_key(512,
    37                           backends.default_backend())
    38  rsa.generate_private_key(3,

References
----------
 - http://csrc.nist.gov/publications/nistpubs/800-131A/sp800-131A.pdf
 - https://security.openstack.org/guidelines/dg_strong-crypto.html
