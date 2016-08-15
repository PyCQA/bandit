# Copyright (c) 2016 Rackspace, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.
"""Utility functions for formatting plugins for Bandit."""

import io

import six


def wrap_file_object(fileobj):
    """Handle differences in Python 2 and 3 around writing bytes."""
    # If it's not an instance of IOBase, we're probably using Python 2 and
    # that is less finnicky about writing text versus bytes to a file.
    if not isinstance(fileobj, io.IOBase):
        return fileobj

    # At this point we're using Python 3 and that will mangle text written to
    # a file written in bytes mode. So, let's check if the file can handle
    # text as opposed to bytes.
    if isinstance(fileobj, io.TextIOBase):
        return fileobj

    # Finally, we've determined that the fileobj passed in cannot handle text,
    # so we use TextIOWrapper to handle the conversion for us.
    return io.TextIOWrapper(fileobj)


def convert_file_contents(text):
    """Convert text to built-in strings on Python 2."""
    if not six.PY2:
        return text
    return str(text.encode('utf-8'))
