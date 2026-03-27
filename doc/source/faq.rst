Frequently Asked Questions
==========================

Under Which Version of Python Should I Install Bandit?
------------------------------------------------------

Bandit itself requires **Python 3.10 or newer** to run. You can install and
run the latest version of Bandit regardless of whether your target project
supports older Python versions (e.g. 3.8 or 3.9). Using the latest Bandit
ensures you benefit from all the most recent security checks.

Bandit uses the `ast` module from Python's standard library in order to
analyze your Python code. The `ast` module is only able to parse Python code
that is valid in the version of the interpreter from which it is imported. In
other words, if you try to use Python 2.7's `ast` module to parse code written
for 3.5 that uses, for example, `yield from` with asyncio, then you'll have
syntax errors that will prevent Bandit from working properly. Alternatively,
if you are relying on 2.7's octal notation of `0777` then you'll have a syntax
error if you run Bandit on 3.x.

In practice, if your project supports Python 3.10+, you can simply run the
latest Bandit under your target Python version. If your project must support
older Python versions (e.g. 3.8, 3.9), you can still run Bandit under
Python 3.10+ — Bandit will correctly parse and analyze code written for those
older versions, as long as the syntax is valid in Python 3.10+. The main
concern is only when the code you are scanning uses syntax **only** available
in a Python version that Bandit cannot run on (e.g. Python 2.x octal notation).
