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

.. table:: Active Test Plugins
   :widths: auto

   ====  ===================================================== ==============  ==============
   ID    Name                                                  Severity        Confidence
   ====  ===================================================== ==============  ==============
   B101  :doc:`b101_assert_used`                               Low             High
   B102  :doc:`b102_exec_used`                                 Medium          High
   B103  :doc:`b103_set_bad_file_permissions`                  Medium to High  High
   B104  :doc:`b104_hardcoded_bind_all_interfaces`             Medium          Medium
   B105  :doc:`b105_hardcoded_password_string`                 Low             Medium
   B106  :doc:`b106_hardcoded_password_funcarg`                Low             Medium
   B107  :doc:`b107_hardcoded_password_default`                Low             Medium
   B108  :doc:`b108_hardcoded_tmp_directory`                   Medium          Medium
   B110  :doc:`b110_try_except_pass`                           Low             High
   B112  :doc:`b112_try_except_continue`                       Low             High
   B113  :doc:`b113_request_without_timeout`                   Medium          Low
   B201  :doc:`b201_flask_debug_true`                          High            Medium
   B324  :doc:`b324_hashlib`                                   Medium to High  High
   B501  :doc:`b501_request_with_no_cert_validation`           High            High
   B502  :doc:`b502_ssl_with_bad_version`                      Medium to High  Medium to High
   B503  :doc:`b503_ssl_with_bad_defaults`                     Medium          Medium
   B504  :doc:`b504_ssl_with_no_version`                       Low             Medium
   B505  :doc:`b505_weak_cryptographic_key`                    Medium to High  High
   B506  :doc:`b506_yaml_load`                                 Medium          High
   B507  :doc:`b507_ssh_no_host_key_verification`              High            Medium
   B508  :doc:`b508_snmp_insecure_version`                     Medium          High
   B509  :doc:`b509_snmp_weak_cryptography`                    Medium          High
   B601  :doc:`b601_paramiko_calls`                            Medium          Medium
   B602  :doc:`b602_subprocess_popen_with_shell_equals_true`   Low to High     High
   B603  :doc:`b603_subprocess_without_shell_equals_true`      Low             High
   B604  :doc:`b604_any_other_function_with_shell_equals_true` Medium          Low
   B605  :doc:`b605_start_process_with_a_shell`                Low to High     High
   B606  :doc:`b606_start_process_with_no_shell`               Low             Medium
   B607  :doc:`b607_start_process_with_partial_path`           Low             High
   B608  :doc:`b608_hardcoded_sql_expressions`                 Medium          Low to Medium
   B609  :doc:`b609_linux_commands_wildcard_injection`         High            Medium
   B610  :doc:`b610_django_extra_used`                         Medium          Medium
   B611  :doc:`b611_django_rawsql_used`                        Medium          Medium
   B612  :doc:`b612_logging_config_insecure_listen`            Medium          High
   B701  :doc:`b701_jinja2_autoescape_false`                   High            Medium to High
   B702  :doc:`b702_use_of_mako_templates`                     Medium          High
   B703  :doc:`b703_django_mark_safe`                          Medium          High
   ====  ===================================================== ==============  ==============


.. table:: Removed Test Plugins
   :widths: auto

   ====  ===================================================== ==============  ==============
   ID    Name                                                  Severity        Confidence
   ====  ===================================================== ==============  ==============
   B109  :doc:`b109_password_config_option_not_marked_secret`  Medium          Low to Medium
   B111  :doc:`b111_execute_with_run_as_root_equals_true`      Low             Medium
   ====  ===================================================== ==============  ==============
