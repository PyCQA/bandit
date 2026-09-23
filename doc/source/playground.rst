Playground
==========

Welcome to the Bandit Playground! This interactive web page allows you to
experience the power of Bandit, a leading Static Application Security Testing
(SAST) tool designed to help identify security issues in Python code. Bandit
scans your code for potential vulnerabilities and provides detailed insights
to help improve the overall security of your application. Whether you’re a
security professional or a developer looking to secure your codebase, this
playground offers a hands-on way to experiment with Bandit’s capabilities
in real-time. Simply paste your Python code into the editor, run the scan,
and explore the results instantly!

.. py-config::

    splashscreen:
        autoclose: true
    packages:
    - bandit

.. raw:: html

    <script type="py-editor" id="editor">
        import ssl

        # Correct
        context = ssl.create_default_context()

        # Incorrect: unverified context
        context = ssl._create_unverified_context()
    </script>

.. py-script::
    :file: playground.py

.. raw:: html

    <div id="output"></div>
