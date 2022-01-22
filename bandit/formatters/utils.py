# Copyright (c) 2016 Rackspace, Inc.
#
# SPDX-License-Identifier: Apache-2.0
"""Utility functions for formatting plugins for Bandit."""
import io


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
