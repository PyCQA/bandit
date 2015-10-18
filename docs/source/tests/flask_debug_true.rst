
flask_debug_true
================

Description
-----------
Running Flask applications in debug mode results in the Werkzeug debugger
being enabled. This includes a feature that allows arbitrary code execution.
Documentation for both Flask [1]_ and Werkzeug [2]_ strongly suggests that
debug mode should never be enabled on production systems.

Operating a production server with debug mode enabled was the probable cause
of the Patreon breach in 2015 [3]_.

Available Since
---------------
 - Bandit v0.15.0

Config Options
--------------
None

Sample Output
-------------
.. code-block:: none

    >> Issue: A Flask app appears to be run with debug=True, which exposes
    the Werkzeug debugger and allows the execution of arbitrary code.
       Severity: High   Confidence: High
          Location: examples/flask_debug.py:10
          9 #bad
          10    app.run(debug=True)
          11

References
----------
.. [1] http://flask.pocoo.org/docs/0.10/quickstart/#debug-mode
.. [2] http://werkzeug.pocoo.org/docs/0.10/debug/
.. [3] http://labs.detectify.com/post/130332638391/how-patreon-got-hacked-publicly-exposed-werkzeug
