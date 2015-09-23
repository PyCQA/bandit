
blacklist_calls
===============

Description
-----------
A number of Python methods and functions are known to have potential security
implications. The blacklist calls plugin test is designed to detect the use of
these methods by scanning code for method calls and checking for their presence
in a configurable blacklist. The scanned calls are fully qualified and
de-aliased prior to checking. To illustrate this, imagine a check for
"evil.thing()" running on the following example code:

.. code-block:: python

    import evil as good

    good.thing()
    thing()

This would generate a warning about calling `evil.thing()` despite the module
being aliased as `good`. It would also not generate a warning on the call to
`thing()` in the local module, as it's fully qualified name will not match.

Each of the provided blacklisted calls can be grouped such that they generate
appropriate warnings (message, severity) and a token `{func}` may be used
in the provided output message, to be replaced with the actual method name.

Due to the nature of the test, confidence is always reported as HIGH

Available Since
---------------
 - Bandit v0.9.0

Config Options
--------------
.. code-block:: yaml

    blacklist_calls:
        bad_name_sets:
            - pickle:
                qualnames:
                    - pickle.loads
                    - pickle.load
                    - pickle.Unpickler
                    - cPickle.loads
                    - cPickle.load
                    - cPickle.Unpickler
                message: >
                    Pickle library appears to be in use, possible security issue.
            - marshal:
                qualnames: [marshal.load, marshal.loads]
                message: >
                    Deserialization with the {func} is possibly dangerous.
                level: LOW

Sample Output
-------------
.. code-block:: none

      >> Issue: Pickle library appears to be in use, possible security issue.

        Severity: Medium   Confidence: High
        Location: ./examples/pickle_deserialize.py:20
      19  serialized = cPickle.dumps({(): []})
      20  print(cPickle.loads(serialized))
      21

References
----------
- https://security.openstack.org
