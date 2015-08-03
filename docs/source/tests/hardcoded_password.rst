
hardcoded_password
==================

Description
-----------
The use of hard-coded passwords increases the possibility of password guessing
tremendously. This plugin test looks for all string literals and checks to see
if they exist in a list of likely default passwords. If they are found in the
list, a LOW severity issue is reported.

Note: this test is very noisy and likely to result in many false positives.

Available Since
---------------
 - Bandit v0.9.0

Config Options
--------------
This plugin test takes a similarly named config block, `hardcoded_password`.
Here a path, `word_list`, can be given to indicate where the default password
word list file may be found.

.. code-block:: yaml

    hardcoded_password:
        # Support for full path, relative path and special "%(site_data_dir)s"
        # substitution (/usr/{local}/share)
        word_list: "%(site_data_dir)s/wordlist/default-passwords"


Sample Output
-------------
.. code-block:: none

    >> Issue: Possible hardcoded password '(root)'
       Severity: Low   Confidence: Low
       Location: ./examples/hardcoded-passwords.py:5
    4 def someFunction2(password):
    5     if password == "root":
    6         print("OK, logged in")

References
----------
- https://www.owasp.org/index.php/Use_of_hard-coded_password
