# Copyright (c) 2013 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0

# THIS FILE IS MANAGED BY THE GLOBAL REQUIREMENTS REPO - DO NOT EDIT
import setuptools

# In python < 2.7.4, a lazy loading of package `pbr` will break
# setuptools if some other modules registered functions in `atexit`.
# solution from: http://bugs.python.org/issue15881#msg170215
try:
    import multiprocessing  # noqa
except ImportError:
    pass

setuptools.setup(
    python_requires='>=3.5',
    setup_requires=['pbr>=2.0.0'],
    pbr=True)
