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


from bandit.blacklists import utils


def gen_blacklist():
    """Generate a list of items to blacklist.

    Methods of this type, "bandit.blacklist" plugins, are used to build a list
    of items that bandit's built in blacklisting tests will use to trigger
    issues. They replace the older blacklist* test plugins and allow
    blacklisted items to have a unique bandit ID for filtering and profile
    usage.

    :return: a dictionary mapping node types to a list of blacklist data
    """

    sets = []
    sets.append(utils.build_conf_dict(
        'telnet', 'B401', ['telnetlib'],
        'A telnet-related module is being imported.  Telnet is '
        'considered insecure. Use SSH or some other encrypted protocol.',
        'HIGH'
        ))

    sets.append(utils.build_conf_dict(
        'ftp', 'B402', ['ftplib'],
        'A FTP-related module is being imported.  FTP is considered '
        'insecure. Use SSH/SFTP/SCP or some other encrypted protocol.',
        'HIGH'
        ))

    sets.append(utils.build_conf_dict(
        'info_libs', 'B403', ['pickle', 'cPickle', 'subprocess', 'Crypto'],
        'Consider possible security implications associated with '
        '{name} module.', 'LOW'
        ))

    # Most of this is based off of Christian Heimes' work on defusedxml:
    #   https://pypi.python.org/pypi/defusedxml/#defusedxml-sax

    sets.append(utils.build_conf_dict(
        'xml_libs', 'B404',
        ['xml.etree.cElementTree',
         'xml.etree.ElementTree',
         'xml.sax.expatreader',
         'xml.sax',
         'xml.dom.expatbuilder',
         'xml.dom.minidom',
         'xml.dom.pulldom',
         'lxml.etree',
         'lxml'],
        'Using {name} to parse untrusted XML data is known to be '
        'vulnerable to XML attacks. Replace {name} with the equivalent '
        'defusedxml package.', 'LOW'
        ))

    sets.append(utils.build_conf_dict(
        'xml_libs_high', 'B405', ['xmlrpclib'],
        'Using {name} to parse untrusted XML data is known to be '
        'vulnerable to XML attacks. Use defused.xmlrpc.monkey_patch() '
        'function to monkey-patch xmlrpclib and mitigate XML '
        'vulnerabilities.', 'HIGH'
        ))

    return {'Import': sets, 'ImportFrom': sets, 'Call': sets}
