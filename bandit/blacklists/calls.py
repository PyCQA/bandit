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
====================================================
Blacklist various Python calls known to be dangerous
====================================================

This balcklist data checks for a number of Python calls known to have possible
security implications. The following blacklist tests are run against any
function calls encoutered in the scanned code base, triggered by encoutering
ast.Call nodes.

B301: pickle
------------

Pickle library appears to be in use, possible security issue.

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Calls                             |  Severity |
+======+=====================+====================================+===========+
| B301 | pickle              | - pickle.loads                     | Medium    |
|      |                     | - pickle.load                      |           |
|      |                     | - pickle.Unpickler                 |           |
|      |                     | - cPickle.loads                    |           |
|      |                     | - cPickle.load                     |           |
|      |                     | - cPickle.Unpickler                |           |
+------+---------------------+------------------------------------+-----------+

B302: marshal
-------------

Deserialization with the marshal module is possibly dangerous.

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Calls                             |  Severity |
+======+=====================+====================================+===========+
| B302 | marshal             | - marshal.load                     | Medium    |
|      |                     | - marshal.loads                    |           |
+------+---------------------+------------------------------------+-----------+

B303: md5
---------

Use of insecure MD2, MD4, or MD5 hash function.

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Calls                             |  Severity |
+======+=====================+====================================+===========+
| B303 | md5                 | - hashlib.md5                      | Medium    |
|      |                     | - Crypto.Hash.MD2.new              |           |
|      |                     | - Crypto.Hash.MD4.new              |           |
|      |                     | - Crypto.Hash.MD5.new              |           |
|      |                     | - cryptography.hazmat.primitives   |           |
|      |                     |   .hashes.MD5                      |           |
+------+---------------------+------------------------------------+-----------+

B304 - B305: ciphers and modes
------------------------------

Use of insecure cipher or cipher mode. Replace with a known secure cipher such
as AES.

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Calls                             |  Severity |
+======+=====================+====================================+===========+
| B304 | ciphers             | - Crypto.Cipher.ARC2.new           | High      |
|      |                     | - Crypto.Cipher.ARC4.new           |           |
|      |                     | - Crypto.Cipher.Blowfish.new       |           |
|      |                     | - Crypto.Cipher.DES.new            |           |
|      |                     | - Crypto.Cipher.XOR.new            |           |
|      |                     | - cryptography.hazmat.primitives   |           |
|      |                     |   .ciphers.algorithms.ARC4         |           |
|      |                     | - cryptography.hazmat.primitives   |           |
|      |                     |   .ciphers.algorithms.Blowfish     |           |
|      |                     | - cryptography.hazmat.primitives   |           |
|      |                     |   .ciphers.algorithms.IDEA         |           |
+------+---------------------+------------------------------------+-----------+
| B305 | cipher_modes        | - cryptography.hazmat.primitives   | Medium    |
|      |                     |   .ciphers.modes.ECB               |           |
+------+---------------------+------------------------------------+-----------+

B306: mktemp_q
--------------

Use of insecure and deprecated function (mktemp).

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Calls                             |  Severity |
+======+=====================+====================================+===========+
| B306 | mktemp_q            | - tempfile.mktemp                  | Medium    |
+------+---------------------+------------------------------------+-----------+

B307: eval
----------

Use of possibly insecure function - consider using safer ast.literal_eval.

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Calls                             |  Severity |
+======+=====================+====================================+===========+
| B307 | eval                | - eval                             | Medium    |
+------+---------------------+------------------------------------+-----------+

B308: mark_safe
---------------

Use of mark_safe() may expose cross-site scripting vulnerabilities and should
be reviewed.

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Calls                             |  Severity |
+======+=====================+====================================+===========+
| B308 | mark_safe           | - mark_safe                        | Medium    |
+------+---------------------+------------------------------------+-----------+

B309: httpsconnection
---------------------

Use of HTTPSConnection does not provide security, see
https://wiki.openstack.org/wiki/OSSN/OSSN-0033

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Calls                             |  Severity |
+======+=====================+====================================+===========+
| B309 | httpsconnection     | - mark_safe                        | Medium    |
|      |                     | - httplib.HTTPSConnection          |           |
|      |                     | - http.client.HTTPSConnection      |           |
|      |                     | - six.moves.http_client            |           |
|      |                     |   .HTTPSConnection                 |           |
+------+---------------------+------------------------------------+-----------+

B310: urllib_urlopen
--------------------

Audit url open for permitted schemes. Allowing use of 'file:'' or custom
schemes is often unexpected.

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Calls                             |  Severity |
+======+=====================+====================================+===========+
| B310 | urllib_urlopen      | - urllib.urlopen                   | Medium    |
|      |                     | - urllib.request.urlopen           |           |
|      |                     | - urllib.urlretrieve               |           |
|      |                     | - urllib.request.urlretrieve       |           |
|      |                     | - urllib.URLopener                 |           |
|      |                     | - urllib.request.URLopener         |           |
|      |                     | - urllib.FancyURLopener            |           |
|      |                     | - urllib.request.FancyURLopener    |           |
|      |                     | - urllib2.urlopen                  |           |
|      |                     | - urllib2.Request                  |           |
|      |                     | - six.moves.urllib.request.urlopen |           |
|      |                     | - six.moves.urllib.request         |           |
|      |                     |   .urlretrieve                     |           |
|      |                     | - six.moves.urllib.request         |           |
|      |                     |   .URLopener                       |           |
|      |                     | - six.moves.urllib.request         |           |
|      |                     |   .FancyURLopener                  |           |
+------+---------------------+------------------------------------+-----------+

B311: random
------------

Standard pseudo-random generators are not suitable for security/cryptographic
purposes.

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Calls                             |  Severity |
+======+=====================+====================================+===========+
| B311 | random              | - random.random                    | Low       |
|      |                     | - random.randrange                 |           |
|      |                     | - random.randint                   |           |
|      |                     | - random.choice                    |           |
|      |                     | - random.uniform                   |           |
|      |                     | - random.triangular                |           |
+------+---------------------+------------------------------------+-----------+

B312: telnetlib
---------------

Telnet-related functions are being called. Telnet is considered insecure. Use
SSH or some other encrypted protocol.

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Calls                             |  Severity |
+======+=====================+====================================+===========+
| B312 | telnetlib           | - telnetlib.\*                     | High      |
+------+---------------------+------------------------------------+-----------+

B313 - B320: XML
----------------

Most of this is based off of Christian Heimes' work on defusedxml:
https://pypi.python.org/pypi/defusedxml/#defusedxml-sax

Using various XLM methods to parse untrusted XML data is known to be vulnerable
to XML attacks. Methods should be replaced with their defusedxml equivalents.

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Calls                             |  Severity |
+======+=====================+====================================+===========+
| B313 | xml_bad_cElementTree| - xml.etree.cElementTree.parse     | Medium    |
|      |                     | - xml.etree.cElementTree.iterparse |           |
|      |                     | - xml.etree.cElementTree.fromstring|           |
|      |                     | - xml.etree.cElementTree.XMLParser |           |
+------+---------------------+------------------------------------+-----------+
| B314 | xml_bad_ElementTree | - xml.etree.ElementTree.parse      | Medium    |
|      |                     | - xml.etree.ElementTree.iterparse  |           |
|      |                     | - xml.etree.ElementTree.fromstring |           |
|      |                     | - xml.etree.ElementTree.XMLParser  |           |
+------+---------------------+------------------------------------+-----------+
| B315 | xml_bad_expatreader | - xml.sax.expatreader.create_parser| Medium    |
+------+---------------------+------------------------------------+-----------+
| B316 | xml_bad_expatbuilder| - xml.dom.expatbuilder.parse       | Medium    |
|      |                     | - xml.dom.expatbuilder.parseString |           |
+------+---------------------+------------------------------------+-----------+
| B317 | xml_bad_sax         | - xml.sax.parse                    | Medium    |
|      |                     | - xml.sax.parseString              |           |
|      |                     | - xml.sax.make_parser              |           |
+------+---------------------+------------------------------------+-----------+
| B318 | xml_bad_minidom     | - xml.dom.minidom.parse            | Medium    |
|      |                     | - xml.dom.minidom.parseString      |           |
+------+---------------------+------------------------------------+-----------+
| B319 | xml_bad_pulldom     | - xml.dom.pulldom.parse            | Medium    |
|      |                     | - xml.dom.pulldom.parseString      |           |
+------+---------------------+------------------------------------+-----------+
| B319 | xml_bad_pulldom     | - xml.dom.pulldom.parse            | Medium    |
|      |                     | - xml.dom.pulldom.parseString      |           |
+------+---------------------+------------------------------------+-----------+
| B320 | xml_bad_etree       | - lxml.etree.parse                 | Medium    |
|      |                     | - lxml.etree.fromstring            |           |
|      |                     | - lxml.etree.RestrictedElement     |           |
|      |                     | - lxml.etree.GlobalParserTLS       |           |
|      |                     | - lxml.etree.getDefaultParser      |           |
|      |                     | - lxml.etree.check_docinfo         |           |
+------+---------------------+------------------------------------+-----------+

B321: ftplib
------------

FTP-related funtions are being called. FTP is considered insecure. Use
SSH/SFTP/SCP or some other encrypted protocol.

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Calls                             |  Severity |
+======+=====================+====================================+===========+
| B321 | ftplib              | - ftplib.\*                        | High      |
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
        'pickle', 'B301',
        ['pickle.loads',
         'pickle.load',
         'pickle.Unpickler',
         'cPickle.loads',
         'cPickle.load',
         'cPickle.Unpickler'],
        'Pickle library appears to be in use, possible security issue.'
        ))

    sets.append(utils.build_conf_dict(
        'marshal', 'B302', ['marshal.load', 'marshal.loads'],
        'Deserialization with the marshal module is possibly dangerous.'
        ))

    sets.append(utils.build_conf_dict(
        'md5', 'B303',
        ['hashlib.md5',
         'Crypto.Hash.MD2.new',
         'Crypto.Hash.MD4.new',
         'Crypto.Hash.MD5.new',
         'cryptography.hazmat.primitives.hashes.MD5'],
        'Use of insecure MD2, MD4, or MD5 hash function.'
        ))

    sets.append(utils.build_conf_dict(
        'ciphers', 'B304',
        ['Crypto.Cipher.ARC2.new',
         'Crypto.Cipher.ARC4.new',
         'Crypto.Cipher.Blowfish.new',
         'Crypto.Cipher.DES.new',
         'Crypto.Cipher.XOR.new',
         'cryptography.hazmat.primitives.ciphers.algorithms.ARC4',
         'cryptography.hazmat.primitives.ciphers.algorithms.Blowfish',
         'cryptography.hazmat.primitives.ciphers.algorithms.IDEA'],
        'Use of insecure cipher {name}. Replace with a known secure'
        ' cipher such as AES.',
        'HIGH'
        ))

    sets.append(utils.build_conf_dict(
        'cipher_modes', 'B305',
        ['cryptography.hazmat.primitives.ciphers.modes.ECB'],
        'Use of insecure cipher mode {name}.'
        ))

    sets.append(utils.build_conf_dict(
        'mktemp_q', 'B306', ['tempfile.mktemp'],
        'Use of insecure and deprecated function (mktemp).'
        ))

    sets.append(utils.build_conf_dict(
        'eval', 'B307', ['eval'],
        'Use of possibly insecure function - consider using safer '
        'ast.literal_eval.'
        ))

    sets.append(utils.build_conf_dict(
        'mark_safe', 'B308', ['mark_safe'],
        'Use of mark_safe() may expose cross-site scripting '
        'vulnerabilities and should be reviewed.'
        ))

    sets.append(utils.build_conf_dict(
        'httpsconnection', 'B309',
        ['httplib.HTTPSConnection',
         'http.client.HTTPSConnection',
         'six.moves.http_client.HTTPSConnection'],
        'Use of HTTPSConnection does not provide security, see '
        'https://wiki.openstack.org/wiki/OSSN/OSSN-0033'
        ))

    sets.append(utils.build_conf_dict(
        'urllib_urlopen', 'B310',
        ['urllib.urlopen',
         'urllib.request.urlopen',
         'urllib.urlretrieve',
         'urllib.request.urlretrieve',
         'urllib.URLopener',
         'urllib.request.URLopener',
         'urllib.FancyURLopener',
         'urllib.request.FancyURLopener',
         'urllib2.urlopen',
         'urllib2.Request',
         'six.moves.urllib.request.urlopen',
         'six.moves.urllib.request.urlretrieve',
         'six.moves.urllib.request.URLopener',
         'six.moves.urllib.request.FancyURLopener'],
        'Audit url open for permitted schemes. Allowing use of file:/ or '
        'custom schemes is often unexpected.'
        ))

    sets.append(utils.build_conf_dict(
        'random', 'B311',
        ['random.random',
         'random.randrange',
         'random.randint',
         'random.choice',
         'random.uniform',
         'random.triangular'],
        'Standard pseudo-random generators are not suitable for '
        'security/cryptographic purposes.',
        'LOW'
        ))

    sets.append(utils.build_conf_dict(
        'telnetlib', 'B312', ['telnetlib.*'],
        'Telnet-related funtions are being called. Telnet is considered '
        'insecure. Use SSH or some other encrypted protocol.',
        'HIGH'
        ))

    # Most of this is based off of Christian Heimes' work on defusedxml:
    #   https://pypi.python.org/pypi/defusedxml/#defusedxml-sax

    xml_msg = ('Using {name} to parse untrusted XML data is known to be '
               'vulnerable to XML attacks. Replace {name} with its '
               'defusedxml equivalent function.')

    sets.append(utils.build_conf_dict(
        'xml_bad_cElementTree', 'B313',
        ['xml.etree.cElementTree.parse',
         'xml.etree.cElementTree.iterparse',
         'xml.etree.cElementTree.fromstring',
         'xml.etree.cElementTree.XMLParser'],
        xml_msg
        ))

    sets.append(utils.build_conf_dict(
        'xml_bad_ElementTree', 'B314',
        ['xml.etree.ElementTree.parse',
         'xml.etree.ElementTree.iterparse',
         'xml.etree.ElementTree.fromstring',
         'xml.etree.ElementTree.XMLParser'],
        xml_msg
        ))

    sets.append(utils.build_conf_dict(
        'xml_bad_expatreader', 'B315', ['xml.sax.expatreader.create_parser'],
        xml_msg
        ))

    sets.append(utils.build_conf_dict(
        'xml_bad_expatbuilder', 'B316',
        ['xml.dom.expatbuilder.parse',
         'xml.dom.expatbuilder.parseString'],
        xml_msg
        ))

    sets.append(utils.build_conf_dict(
        'xml_bad_sax', 'B317',
        ['xml.sax.parse',
         'xml.sax.parseString',
         'xml.sax.make_parser'],
        xml_msg
        ))

    sets.append(utils.build_conf_dict(
        'xml_bad_minidom', 'B318',
        ['xml.dom.minidom.parse',
         'xml.dom.minidom.parseString'],
        xml_msg
        ))

    sets.append(utils.build_conf_dict(
        'xml_bad_pulldom', 'B319',
        ['xml.dom.pulldom.parse',
         'xml.dom.pulldom.parseString'],
        xml_msg
        ))

    sets.append(utils.build_conf_dict(
        'xml_bad_etree', 'B320',
        ['lxml.etree.parse',
         'lxml.etree.fromstring',
         'lxml.etree.RestrictedElement',
         'lxml.etree.GlobalParserTLS',
         'lxml.etree.getDefaultParser',
         'lxml.etree.check_docinfo'],
        xml_msg
        ))

    # end of XML tests

    sets.append(utils.build_conf_dict(
        'ftplib', 'B321', ['ftplib.*'],
        'FTP-related funtions are being called. FTP is considered '
        'insecure. Use SSH/SFTP/SCP or some other encrypted protocol.',
        'HIGH'
        ))

    return {'Call': sets}
