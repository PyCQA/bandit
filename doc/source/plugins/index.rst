Test Plugins
============

Bandit supports many different tests to detect various security issues in
python code. These tests are created as plugins and new ones can be created to
extend the functionality offered by bandit today.

Writing Tests
-------------
To write a test:
 - Identify a vulnerability to build a test for, and create a new file in
   examples/ that contains one or more cases of that vulnerability.
 - Create a new Python source file to contain your test, you can reference
   existing tests for examples.
 - Consider the vulnerability you're testing for, mark the function with one
   or more of the appropriate decorators:

  - @checks('Call')
  - @checks('Import', 'ImportFrom')
  - @checks('Str')

 - Register your plugin using the `bandit.plugins` entry point, see example.
 - The function that you create should take a parameter "context" which is
   an instance of the context class you can query for information about the
   current element being examined.  You can also get the raw AST node for
   more advanced use cases.  Please see the `context.py` file for more.
 - Extend your Bandit configuration file as needed to support your new test.
 - Execute Bandit against the test file you defined in `examples/` and ensure
   that it detects the vulnerability.  Consider variations on how this
   vulnerability might present itself and extend the example file and the test
   function accordingly.

Config Generation
-----------------
In Bandit 1.0+ config files are optional. Plugins that need config settings are
required to implement a module global `gen_config` function. This function is
called with a single parameter, the test plugin name. It should return a
dictionary with keys being the config option names and values being the default
settings for each option. An example `gen_config` might look like the following:

.. code-block:: python

    def gen_config(name):
        if name == 'try_except_continue':
            return {'check_typed_exception': False}


When no config file is specified, or when the chosen file has no section
pertaining to a given plugin, `gen_config` will be called to provide defaults.

The config file generation tool `bandit-config-generator` will also call
`gen_config` on all discovered plugins to produce template config blocks. If
the defaults are acceptable then these blocks may be deleted to create a
minimal configuration, or otherwise edited as needed. The above example would
produce the following config snippet.

.. code-block:: yaml

    try_except_continue: {check_typed_exception: false}


Example Test Plugin
-------------------

.. code-block:: python

    @bandit.checks('Call')
    def prohibit_unsafe_deserialization(context):
        if 'unsafe_load' in context.call_function_name_qual:
            return bandit.Issue(
                severity=bandit.HIGH,
                confidence=bandit.HIGH,
                text="Unsafe deserialization detected."
            )

To register your plugin, you have two options:

1. If you're using setuptools directly, add something like the following to
   your `setup` call::

        # If you have an imaginary bson formatter in the bandit_bson module
        # and a function called `formatter`.
        entry_points={'bandit.formatters': ['bson = bandit_bson:formatter']}
        # Or a check for using mako templates in bandit_mako that
        entry_points={'bandit.plugins': ['mako = bandit_mako']}

2. If you're using pbr, add something like the following to your `setup.cfg`
   file::

        [entry_points]
        bandit.formatters =
            bson = bandit_bson:formatter
        bandit.plugins =
            mako = bandit_mako


Plugin ID Groupings
-------------------

=======  ===========
ID       Description
=======  ===========
B1xx     misc tests
B2xx     application/framework misconfiguration
B3xx     blacklists (calls)
B4xx     blacklists (imports)
B5xx     cryptography
B6xx     injection
B7xx     XSS
=======  ===========


Complete Test Plugin Listing
----------------------------

.. toctree::
   :maxdepth: 1
   :glob:

   *
