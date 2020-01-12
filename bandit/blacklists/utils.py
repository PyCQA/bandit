# -*- coding:utf-8 -*-
#
# Copyright 2016 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0


def build_conf_dict(name, bid, qualnames, message, level='MEDIUM'):
    """Build and return a blacklist configuration dict."""

    return {'name': name, 'id': bid, 'message': message,
            'qualnames': qualnames, 'level': level}
