GitHub Actions Workflow for Bandit
==================================

This document provides a minimal complete example workflow for 
setting up a Code Scanning action using Bandit through GitHub 
Actions. It leverages PyCQA's `bandit-action  
<https://github.com/PyCQA/bandit-action>`_ for seamless 
integration.  

Example YAML Code for GitHub Actions Pipeline
---------------------------------------------

Below is an example configuration for the GitHub Actions pipeline:

.. code-block:: yaml

    name: Bandit

    on:
        workflow_dispatch:

    jobs:
        analyze:
            runs-on: ubuntu-latest
            permissions:
                # Required for all workflows
                security-events: write
                # Only required for workflows in private repositories
                actions: read
                contents: read
            steps:
                - name: Perform Bandit Analysis
                  uses: PyCQA/bandit-action@v1

Inputs
======

Below is a list of available inputs for the `bandit-action` and 
their descriptions:  

.. list-table::
   :header-rows: 1
   :widths: 20 50 10 20

   * - Name
     - Description
     - Required
     - Default Value
   * - ``configfile``
     - Config file to use for selecting plugins and overriding defaults.
     - False
     - ``DEFAULT``
   * - ``profile``
     - Profile to use (defaults to executing all tests).
     - False
     - ``DEFAULT``
   * - ``tests``
     - Comma-separated list of test IDs to run.
     - False
     - ``DEFAULT``
   * - ``skips``
     - Comma-separated list of test IDs to skip.
     - False
     - ``DEFAULT``
   * - ``severity``
     - Report only issues of a given severity level or higher. Options include ``all``, ``high``, ``medium``, ``low``. 
       Note: ``all`` and ``low`` may produce similar results, but undefined rules will not be listed under ``low``.
     - False
     - ``DEFAULT``
   * - ``confidence``
     - Report only issues of a given confidence level or higher. Options include ``all``, ``high``, ``medium``, ``low``. 
       Note: ``all`` and ``low`` may produce similar results, but undefined rules will not be listed under ``low``.
     - False
     - ``DEFAULT``
   * - ``exclude``
     - Comma-separated list of paths (glob patterns supported) to exclude from the scan. These are in addition to excluded paths provided in the config file.
     - False
     - ``.svn,CVS,.bzr,.hg,.git,__pycache__,.tox,.eggs,*.egg``
   * - ``baseline``
     - Path of a baseline report to compare against (only JSON-formatted files are accepted).
     - False
     - ``DEFAULT``
   * - ``ini``
     - Path to a ``.bandit`` file that supplies command-line arguments.
     - False
     - ``DEFAULT``
   * - ``targets``
     - Source file(s) or directory(s) to be tested.
     - False
     - ``.``