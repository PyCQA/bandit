Getting Started
===============

Installation
------------
Bandit is distributed on PyPI. The best way to install it is with pip:


Create a virtual environment (optional)::

    virtualenv bandit-env
    python3 -m venv bandit-env
    # And activate it:
    source bandit-env/bin/activate

Install Bandit::

    pip install bandit
    pip3 install bandit

Run Bandit::

    bandit -r path/to/your/code


Bandit can also be installed from source. To do so, download the source tarball
from PyPI, then install it::

    python setup.py install


Usage
-----
Example usage across a code tree::

    bandit -r ~/your_repos/project

Example usage across the ``examples/`` directory, showing three lines of
context and only reporting on the high-severity issues::

    bandit examples/*.py -n 3 -lll

Bandit can be run with profiles. To run Bandit against the examples directory
using only the plugins listed in the ``ShellInjection`` profile::

    bandit examples/*.py -p ShellInjection

Bandit also supports passing lines of code to scan using standard input. To
run Bandit with standard input::

    cat examples/imports.py | bandit -

For more usage information::

    bandit -h


Baseline
--------
Bandit allows specifying the path of a baseline report to compare against using the base line argument (i.e. ``-b BASELINE`` or ``--baseline BASELINE``).

::

   bandit -b BASELINE

This is useful for ignoring known vulnerabilities that you believe are non-issues (e.g. a cleartext password in a unit test). To generate a baseline report simply run Bandit with the output format set to ``json`` (only JSON-formatted files are accepted as a baseline) and output file path specified:

::

    bandit -f json -o PATH_TO_OUTPUT_FILE


Version control integration
---------------------------

Use `pre-commit <https://pre-commit.com/>`_. Once you `have it
installed <https://pre-commit.com/#install>`_, add this to the
`.pre-commit-config.yaml` in your repository
(be sure to update `rev` to point to a real git tag/revision!)::

    repos:
    -   repo: https://github.com/PyCQA/bandit
        rev: '' # Update me!
        hooks:
        - id: bandit


Then run `pre-commit install` and you're ready to go.
