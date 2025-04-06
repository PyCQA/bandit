# Copyright (c) 2013 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0
import os

import setuptools


data_files = []
man_path = "doc/build/man/bandit.1"
if os.path.isfile(man_path):
    data_files.append(("share/man/man1", [man_path]))


setuptools.setup(
    python_requires=">=3.9",
    setup_requires=["pbr>=2.0.0"],
    pbr=True,
    data_files=data_files,
)
