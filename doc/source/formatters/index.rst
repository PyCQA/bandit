Bandit Report Formatters
========================

Bandit supports many different formatters to output various security issues in
python code. These formatters are created as plugins and new ones can be
created to extend the functionality offered by bandit today.

Example Formatter
-----------------

.. code-block:: python

    def report(manager, filename, sev_level, conf_level, lines=-1,
               out_format='bson'):
        result = bson.dumps(issues)
        with utils.output_file(filename, 'w') as fout:
            fout.write(result)

To register your plugin, you have two options:

1. If you're using setuptools directly, add something like the following to
   your `setup` call::

        # If you have an imaginary bson formatter in the bandit_bson module
        # and a function called `formatter`.
        entry_points={'bandit.formatters': ['bson = bandit_bson:formatter']}

2. If you're using pbr, add something like the following to your `setup.cfg`
   file::

        [entry_points]
        bandit.formatters =
            bson = bandit_bson:formatter


Complete Formatter Listing
----------------------------

.. toctree::
   :maxdepth: 1
   :glob:

   *
