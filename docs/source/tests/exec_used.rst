exec_used
=========

Description
-----------
This plugin test checks for the use of Python's `exec` method or keyword. The
Python docs succinctly describe why the use of `exec` is risky:

 - `This statement supports dynamic execution of Python code.` [1]_

Available Since
---------------
 - Bandit v0.9.0

Config Options
--------------
None

Sample Output
-------------
.. code-block:: none

    >> Issue: Use of exec detected.
       Severity: Medium   Confidence: High
       Location: ./examples/exec-py2.py:2
    1 exec("do evil")
    2 exec "do evil"

References
----------
.. [1] https://docs.python.org/2.0/ref/exec.html
.. [2] TODO : add info on exec and similar to sec best practice and link here
