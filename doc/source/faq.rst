Frequently Asked Questions
==========================

Under Which Version of Python Should I Install Bandit?
------------------------------------------------------

The answer to this question depends on the project(s) you will be running
Bandit against. If your project is only compatible with Python 3.9, you
should install Bandit to run under Python 3.9. If your project is only
compatible with Python 3.10, then use 3.10 respectively. If your project
supports both, you *could* run Bandit with both versions but you don't have to.

Bandit uses the `ast` module from Python's standard library in order to
analyze your Python code. The `ast` module is only able to parse Python code
that is valid in the version of the interpreter from which it is imported. In
other words, if you try to use Python 2.7's `ast` module to parse code written
for 3.5 that uses, for example, `yield from` with asyncio, then you'll have
syntax errors that will prevent Bandit from working properly. Alternatively,
if you are relying on 2.7's octal notation of `0777` then you'll have a syntax
error if you run Bandit on 3.x.
