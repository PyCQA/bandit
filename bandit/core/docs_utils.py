# -*- coding:utf-8 -*-
#
# Copyright 2016 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# where our docs are hosted
BASE_URL = 'https://docs.openstack.org/bandit/latest/'


def get_url(bid):
    # NOTE(tkelsey): for some reason this import can't be found when stevedore
    # loads up the formatter plugin that imports this file. It is available
    # later though.
    from bandit.core import extension_loader

    info = extension_loader.MANAGER.plugins_by_id.get(bid)
    if info is not None:
        return BASE_URL + ('plugins/%s.html' % info.plugin.__name__)

    info = extension_loader.MANAGER.blacklist_by_id.get(bid)
    if info is not None:
        template = 'blacklists/blacklist_{kind}.html#{id}-{name}'
        info['name'] = info['name'].replace('_', '-')

        if info['id'].startswith('B3'):  # B3XX
            # Some of the links are combined, so we have exception cases
            if info['id'] in ['B304', 'B305']:
                info['id'] = 'b304-b305'
                info['name'] = 'ciphers-and-modes'
            elif info['id'] in ['B313', 'B314', 'B315', 'B316', 'B317',
                                'B318', 'B319', 'B320']:
                info['id'] = 'b313-b320'
            ext = template.format(
                kind='calls', id=info['id'], name=info['name'])
        else:
            ext = template.format(
                kind='imports', id=info['id'], name=info['name'])

        return BASE_URL + ext.lower()

    return BASE_URL  # no idea, give the docs main page
