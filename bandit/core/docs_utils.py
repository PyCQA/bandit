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
base_url = 'http://docs.openstack.org/developer/bandit/'


def get_url(bid):
    # NOTE(tkelsey): for some reason this import can't be found when stevedore
    # loads up the formatter plugin that imports this file. It is available
    # later though.
    from bandit.core import extension_loader

    info = extension_loader.MANAGER.plugins_by_id.get(bid, None)
    if info is not None:
        return base_url + ('plugins/%s.html' % info.plugin.__name__)

    info = extension_loader.MANAGER.blacklist_by_id.get(bid, None)
    if info is not None:
        template = 'blacklists/blacklist_{kind}.html#{id}-{name}'
        if info['id'].startswith('B3'):  # B3XX
            ext = template.format(
                kind='calls', id=info['id'], name=info['name'])
        else:
            ext = template.format(
                kind='imports', id=info['id'], name=info['name'])

        return base_url + ext.lower()

    return base_url  # no idea, give the docs main page
