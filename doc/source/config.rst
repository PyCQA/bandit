Configuration
=============
Bandit is designed to be configurable and cover a wide range of needs, it may
be used as either a local developer utility or as part of a full CI/CD
pipeline. To provide for these various usage scenarios Bandit can be configured
via the 'bandit.yaml' file. Here we can choose the specific test plugins to
run, the test parameters, and the desired output report format. These choices
may be grouped into configuration profiles that can be selected at run time.

Upon startup, unless given a specific path via the command line ``-c`` option,
Bandit will search for a configuration file in the following locations:

 #. Current directory
 #. User home directory (usually ~/.config/ )
 #. Bundled config (the bandit library config, normally site-packages)

Configuring Test Plugins
------------------------
Bandit's configuration file is written in `YAML <http://yaml.org/>`_ and options
for each plugin test are provided under a section named to match the test
method. For example, given a test plugin called 'try_except_pass' its
configuration section might look like the following:

.. code-block:: yaml

    try_except_pass:
      check_typed_exception: True

The specific content of the configuration block is determined by the plugin
test itself. See the `plugin test list <tests/index.html>`_ for complete
information on configuring each one.

Test Profiles
-------------
Bandit defaults to running all available test plugins. However, this behavior
can be overridden by grouping tests into named sets, known as profiles, and
specifying a profile using the ``-p`` command line option. When running with a
profile only those tests explicitly listed in the chosen profile will be run.
To define a profile set, create a named entry under the 'profiles' section of
the config. For example the following defines two profiles, ``XSS`` and
``SqlInjection``.

.. code-block:: yaml

    profiles:
      XSS:
        include:
          - jinja2_autoescape_false
          - use_of_mako_templates

      SqlInjection:
        include:
          - hardcoded_sql_expressions

Again, test plugins are referred to using their method name. Thus in the above
example we create two profiles, the first running 'jinja2_autoescape_false' and
'use_of_mako_templates' and the second running just 'hardcoded_sql_expressions'.


Report Format Plugins
---------------------
In order to integrate with various CI/CD pipelines, Bandit provides a facility
to build pluggable output formatters. A well written formatter should respect
all of the report configuration options given here, however they may also
expose their own specific configuration choices. Please see the `complete list
of formatters <formatters/index.html>`_ for details.

+---------------+------------------------------------------------------------+
| Option        | Description                                                |
+===============+============================================================+
| TBD           |                                                            |
+---------------+------------------------------------------------------------+


Misc Options
------------
The following miscellaneous options are available:

+---------------------+------------------------------------------------------+
| Option              | Description                                          |
+=====================+======================================================+
| include             | Globs of files which should be analyzed,             |
|                     | typically this will be '\*.py' and '\*.pyw'.         |
+---------------------+------------------------------------------------------+
| exclude_dirs        | A list of strings, which if found in the path will   |
|                     | cause files to be excluded.                          |
+---------------------+------------------------------------------------------+
| show_progress_every | Optionally show progress every X files.              |
|                     | If not given it will default to 50 files.            |
+---------------------+------------------------------------------------------+
| log_format          | Optional log format string, if not given defaults    |
|                     | to ``"[%(module)s]\\t%(levelname)s\\t%(message)s"``. |
+---------------------+------------------------------------------------------+
| output_colors       | Optional terminal escape sequences to display colors,|
|                     | if not given defaults will be used.                  |
+---------------------+------------------------------------------------------+

Generating a default configuration
----------------------------------
Some users might want to use a 'generic' configuration for bandit. Using
'bandit-config-generator', it is possible to generate such a configuration
without writing a whole bandit.yaml. Instead, one can write a minimal
configuration file (named 'minimal.yaml', for instance) that looks like
this:

.. code-block:: yaml

    profile_name: my-bandit-config
    exclude_checkers: [assert_used, try_except_pass]

Then, it is possible to call 'bandit-config-generator' to generate a valid
configuration:

.. code-block:: bash

    bandit-config-generator --out my-bandit.yaml bandit.yaml minimal.yaml

Where 'bandit.yaml' is the full configuration example provided by bandit.

The following options are available:

+---------------------+------------------------------------------------------+
| Option              | Description                                          |
+=====================+======================================================+
| profile_name        | The name of the profile that will be generated.      |
+---------------------+------------------------------------------------------+
| exclude_checkers    | A list of checkers to disable.                       |
+---------------------+------------------------------------------------------+
