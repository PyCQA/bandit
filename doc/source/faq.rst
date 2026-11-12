Frequently Asked Questions
==========================

Under Which Version of Python Should I Install Bandit?
------------------------------------------------------

The answer to this question depends on the project(s) you will be running
Bandit against. If your project is only compatible with Python 3.9, you
should install Bandit to run under Python 3.9. If your project is only
compatible with Python 3.10, then use 3.10 respectively. If your project
supports both, you *could* run Bandit with both versions but you don't have to.

The important compatibility boundary is whether Bandit's Python interpreter
can parse the source code being scanned. For example, if a project supports
Python 3.8 through 3.12 and does not contain syntax that is specific to only
one of those versions, running a current Bandit release on a Python version it
supports is normally enough and lets you benefit from newer checks. Running
Bandit across multiple Python interpreters is only useful when the code being
scanned uses syntax that cannot be parsed by a single interpreter version, or
when you intentionally keep different source files for different Python
versions.

Bandit uses the `ast` module from Python's standard library in order to
analyze your Python code. The `ast` module is only able to parse Python code
that is valid in the version of the interpreter from which it is imported. In
other words, if you try to use Python 2.7's `ast` module to parse code written
for 3.5 that uses, for example, `yield from` with asyncio, then you'll have
syntax errors that will prevent Bandit from working properly. Alternatively,
if you are relying on 2.7's octal notation of `0777` then you'll have a syntax
error if you run Bandit on 3.x.
