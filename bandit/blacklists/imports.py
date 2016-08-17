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

r"""
======================================================
Blacklist various Python imports known to be dangerous
======================================================

This blacklist data checks for a number of Python modules known to have
possible security implications. The following blacklist tests are run against
any import statements or calls encountered in the scanned code base.

Note that the XML rules listed here are mostly based off of Christian Heimes'
work on defusedxml: https://pypi.python.org/pypi/defusedxml

B401: import_telnetlib
----------------------

A telnet-related module is being imported. Telnet is considered insecure. Use
SSH or some other encrypted protocol.

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Imports                           |  Severity |
+======+=====================+====================================+===========+
| B401 | import_telnetlib    | - telnetlib                        | high      |
+------+---------------------+------------------------------------+-----------+

B402: import_ftplib
-------------------
A FTP-related module is being imported.  FTP is considered insecure. Use
SSH/SFTP/SCP or some other encrypted protocol.

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Imports                           |  Severity |
+======+=====================+====================================+===========+
| B402 | inport_ftplib       | - ftplib                           | high      |
+------+---------------------+------------------------------------+-----------+

B403: import_pickle
-------------------

Consider possible security implications associated with these modules.

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Imports                           |  Severity |
+======+=====================+====================================+===========+
| B403 | import_pickle       | - pickle                           | low       |
|      |                     | - cPickle                          |           |
+------+---------------------+------------------------------------+-----------+

B404: import_subprocess
-----------------------

Consider possible security implications associated with these modules.

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Imports                           |  Severity |
+======+=====================+====================================+===========+
| B404 | import_subprocess   | - subprocess                       | low       |
+------+---------------------+------------------------------------+-----------+


B405: import_xml_etree
----------------------

Using various methods to parse untrusted XML data is known to be vulnerable to
XML attacks. Replace vulnerable imports with the equivalent defusedxml package,
or make sure defusedxml.defuse_stdlib() is called.

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Imports                           |  Severity |
+======+=====================+====================================+===========+
| B405 | import_xml_etree    | - xml.etree.cElementTree           | low       |
|      |                     | - xml.etree.ElementTree            |           |
+------+---------------------+------------------------------------+-----------+

B406: import_xml_sax
--------------------

Using various methods to parse untrusted XML data is known to be vulnerable to
XML attacks. Replace vulnerable imports with the equivalent defusedxml package,
or make sure defusedxml.defuse_stdlib() is called.

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Imports                           |  Severity |
+======+=====================+====================================+===========+
| B406 | import_xml_sax      | - xml.sax                          | low       |
+------+---------------------+------------------------------------+-----------+

B407: import_xml_expat
----------------------

Using various methods to parse untrusted XML data is known to be vulnerable to
XML attacks. Replace vulnerable imports with the equivalent defusedxml package,
or make sure defusedxml.defuse_stdlib() is called.

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Imports                           |  Severity |
+======+=====================+====================================+===========+
| B407 | import_xml_expat    | - xml.dom.expatbuilder             | low       |
+------+---------------------+------------------------------------+-----------+

B408: import_xml_minidom
------------------------

Using various methods to parse untrusted XML data is known to be vulnerable to
XML attacks. Replace vulnerable imports with the equivalent defusedxml package,
or make sure defusedxml.defuse_stdlib() is called.


+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Imports                           |  Severity |
+======+=====================+====================================+===========+
| B408 | import_xml_minidom  | - xml.dom.minidom                  | low       |
+------+---------------------+------------------------------------+-----------+

B409: import_xml_pulldom
------------------------

Using various methods to parse untrusted XML data is known to be vulnerable to
XML attacks. Replace vulnerable imports with the equivalent defusedxml package,
or make sure defusedxml.defuse_stdlib() is called.

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Imports                           |  Severity |
+======+=====================+====================================+===========+
| B409 | import_xml_pulldom  | - xml.dom.pulldom                  | low       |
+------+---------------------+------------------------------------+-----------+

B410: import_lxml
-----------------

Using various methods to parse untrusted XML data is known to be vulnerable to
XML attacks. Replace vulnerable imports with the equivalent defusedxml package.

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Imports                           |  Severity |
+======+=====================+====================================+===========+
| B410 | import_lxml         | - lxml                             | low       |
+------+---------------------+------------------------------------+-----------+

B411: import_xmlrpclib
----------------------

XMLRPC is particularly dangerous as it is also concerned with communicating
data over a network. Use defused.xmlrpc.monkey_patch() function to monkey-patch
xmlrpclib and mitigate remote XML attacks.

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Imports                           |  Severity |
+======+=====================+====================================+===========+
| B411 | import_xmlrpclib    | - xmlrpclib                        | high      |
+------+---------------------+------------------------------------+-----------+

B412: import_httpoxy
--------------------
httpoxy is a set of vulnerabilities that affect application code running in
CGI, or CGI-like environments. The use of CGI for web applications should be
avoided to prevent this class of attack. More details are available
at https://httpoxy.org/.

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Imports                           |  Severity |
+======+=====================+====================================+===========+
| B412 | import_httpoxy      | - wsgiref.handlers.CGIHandler      | high      |
|      |                     | - twisted.web.twcgi.CGIScript      |           |
+------+---------------------+------------------------------------+-----------+

"""

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
        'import_telnetlib', 'B401', ['telnetlib'],
        'A telnet-related module is being imported.  Telnet is '
        'considered insecure. Use SSH or some other encrypted protocol.',
        'HIGH'
        ))

    sets.append(utils.build_conf_dict(
        'import_ftplib', 'B402', ['ftplib'],
        'A FTP-related module is being imported.  FTP is considered '
        'insecure. Use SSH/SFTP/SCP or some other encrypted protocol.',
        'HIGH'
        ))

    sets.append(utils.build_conf_dict(
        'import_pickle', 'B403', ['pickle', 'cPickle'],
        'Consider possible security implications associated with '
        '{name} module.', 'LOW'
        ))

    sets.append(utils.build_conf_dict(
        'import_subprocess', 'B404', ['subprocess'],
        'Consider possible security implications associated with '
        '{name} module.', 'LOW'
        ))

    # Most of this is based off of Christian Heimes' work on defusedxml:
    #   https://pypi.python.org/pypi/defusedxml/#defusedxml-sax

    xml_msg = ('Using {name} to parse untrusted XML data is known to be '
               'vulnerable to XML attacks. Replace {name} with the equivalent '
               'defusedxml package, or make sure defusedxml.defuse_stdlib() '
               'is called.')
    lxml_msg = ('Using {name} to parse untrusted XML data is known to be '
                'vulnerable to XML attacks. Replace {name} with the '
                'equivalent defusedxml package.')

    sets.append(utils.build_conf_dict(
        'import_xml_etree', 'B405',
        ['xml.etree.cElementTree', 'xml.etree.ElementTree'], xml_msg, 'LOW'))

    sets.append(utils.build_conf_dict(
        'import_xml_sax', 'B406', ['xml.sax'], xml_msg, 'LOW'))

    sets.append(utils.build_conf_dict(
        'import_xml_expat', 'B407', ['xml.dom.expatbuilder'], xml_msg, 'LOW'))

    sets.append(utils.build_conf_dict(
        'import_xml_minidom', 'B408', ['xml.dom.minidom'], xml_msg, 'LOW'))

    sets.append(utils.build_conf_dict(
        'import_xml_pulldom', 'B409', ['xml.dom.pulldom'], xml_msg, 'LOW'))

    sets.append(utils.build_conf_dict(
        'import_lxml', 'B410', ['lxml'], lxml_msg, 'LOW'))

    sets.append(utils.build_conf_dict(
        'import_xmlrpclib', 'B411', ['xmlrpclib'],
        'Using {name} to parse untrusted XML data is known to be '
        'vulnerable to XML attacks. Use defused.xmlrpc.monkey_patch() '
        'function to monkey-patch xmlrpclib and mitigate XML '
        'vulnerabilities.', 'HIGH'))

    sets.append(utils.build_conf_dict(
        'import_httpoxy', 'B412',
        ['wsgiref.handlers.CGIHandler', 'twisted.web.twcgi.CGIScript',
         'twisted.web.twcgi.CGIDirectory'],
        'Consider possible security implications associated with '
        '{name} module.', 'HIGH'
        ))

    return {'Import': sets, 'ImportFrom': sets, 'Call': sets}
