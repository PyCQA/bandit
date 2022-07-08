.. image:: https://raw.githubusercontent.com/pycqa/bandit/main/logo/logotype-sm.png
    :alt: Bandit

======

.. image:: https://github.com/PyCQA/bandit/workflows/Build%20and%20Test%20Bandit/badge.svg
    :target: https://github.com/PyCQA/bandit/actions?query=workflow%3A%22Build+and+Test+Bandit%22
    :alt: Build Status

.. image:: https://readthedocs.org/projects/bandit/badge/?version=latest
    :target: https://readthedocs.org/projects/bandit/
    :alt: Docs Status

.. image:: https://img.shields.io/pypi/v/bandit.svg
    :target: https://pypi.org/project/bandit/
    :alt: Latest Version

.. image:: https://img.shields.io/pypi/pyversions/bandit.svg
    :target: https://pypi.org/project/bandit/
    :alt: Python Versions

.. image:: https://img.shields.io/pypi/format/bandit.svg
    :target: https://pypi.org/project/bandit/
    :alt: Format

.. image:: https://img.shields.io/badge/license-Apache%202-blue.svg
    :target: https://github.com/PyCQA/bandit/blob/main/LICENSE
    :alt: License

.. image:: https://img.shields.io/discord/825463413634891776.svg
    :target: https://discord.gg/qYxpadCgkx
    :alt: Discord

A security linter from PyCQA

* Free software: Apache license
* Documentation: https://bandit.readthedocs.io/en/latest/
* Source: https://github.com/PyCQA/bandit
* Bugs: https://github.com/PyCQA/bandit/issues
* Contributing: https://github.com/PyCQA/bandit/blob/main/CONTRIBUTING.md

Overview
--------

Bandit is a tool designed to find common security issues in Python code. To do
this Bandit processes each file, builds an AST from it, and runs appropriate
plugins against the AST nodes. Once Bandit has finished scanning all the files
it generates a report.

Bandit was originally developed within the OpenStack Security Project and
later rehomed to PyCQA.

.. image:: https://raw.githubusercontent.com/pycqa/bandit/main/bandit-terminal.png
    :alt: Bandit Example Screen Shot

Show Your Style
---------------

.. image:: https://img.shields.io/badge/security-bandit-yellow.svg
    :target: https://github.com/PyCQA/bandit
    :alt: Security Status

Use our badge in your project's README!

using Markdown::

    [![security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)

using RST::

    .. image:: https://img.shields.io/badge/security-bandit-yellow.svg
        :target: https://github.com/PyCQA/bandit
        :alt: Security Status

References
----------

Python AST module documentation: https://docs.python.org/3/library/ast.html

Green Tree Snakes - the missing Python AST docs:
https://greentreesnakes.readthedocs.org/en/latest/

Documentation of the various types of AST nodes that Bandit currently covers
or could be extended to cover:
https://greentreesnakes.readthedocs.org/en/latest/nodes.html
