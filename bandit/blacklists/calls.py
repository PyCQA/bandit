# -*- coding:utf-8 -*-
#
# Copyright 2016 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0
r"""
====================================================
Blacklist various Python calls known to be dangerous
====================================================

This blacklist data checks for a number of Python calls known to have possible
security implications. The following blacklist tests are run against any
function calls encoutered in the scanned code base, triggered by encoutering
ast.Call nodes.

B301: pickle
------------

Pickle and modules that wrap it can be unsafe when used to
deserialize untrusted data, possible security issue.

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Calls                             |  Severity |
+======+=====================+====================================+===========+
| B301 | pickle              | - pickle.loads                     | Medium    |
|      |                     | - pickle.load                      |           |
|      |                     | - pickle.Unpickler                 |           |
|      |                     | - cPickle.loads                    |           |
|      |                     | - cPickle.load                     |           |
|      |                     | - cPickle.Unpickler                |           |
|      |                     | - dill.loads                       |           |
|      |                     | - dill.load                        |           |
|      |                     | - dill.Unpickler                   |           |
|      |                     | - shelve.open                      |           |
|      |                     | - shelve.DbfilenameShelf           |           |
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

Use of insecure MD2, MD4, MD5, or SHA1 hash function.

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Calls                             |  Severity |
+======+=====================+====================================+===========+
| B303 | md5                 | - hashlib.md5                      | Medium    |
|      |                     | - hashlib.sha1                     |           |
|      |                     | - Crypto.Hash.MD2.new              |           |
|      |                     | - Crypto.Hash.MD4.new              |           |
|      |                     | - Crypto.Hash.MD5.new              |           |
|      |                     | - Crypto.Hash.SHA.new              |           |
|      |                     | - Cryptodome.Hash.MD2.new          |           |
|      |                     | - Cryptodome.Hash.MD4.new          |           |
|      |                     | - Cryptodome.Hash.MD5.new          |           |
|      |                     | - Cryptodome.Hash.SHA.new          |           |
|      |                     | - cryptography.hazmat.primitives   |           |
|      |                     |   .hashes.MD5                      |           |
|      |                     | - cryptography.hazmat.primitives   |           |
|      |                     |   .hashes.SHA1                     |           |
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
|      |                     | - Cryptodome.Cipher.ARC2.new       |           |
|      |                     | - Cryptodome.Cipher.ARC4.new       |           |
|      |                     | - Cryptodome.Cipher.Blowfish.new   |           |
|      |                     | - Cryptodome.Cipher.DES.new        |           |
|      |                     | - Cryptodome.Cipher.XOR.new        |           |
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
| B308 | mark_safe           | - django.utils.safestring.mark_safe| Medium    |
+------+---------------------+------------------------------------+-----------+

B309: httpsconnection
---------------------

Use of HTTPSConnection on older versions of Python prior to 2.7.9 and 3.4.3 do
not provide security, see https://wiki.openstack.org/wiki/OSSN/OSSN-0033

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Calls                             |  Severity |
+======+=====================+====================================+===========+
| B309 | httpsconnection     | - httplib.HTTPSConnection          | Medium    |
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
|      |                     | - random.choices                   |           |
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
https://pypi.org/project/defusedxml/#defusedxml-sax

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
| B320 | xml_bad_etree       | - lxml.etree.parse                 | Medium    |
|      |                     | - lxml.etree.fromstring            |           |
|      |                     | - lxml.etree.RestrictedElement     |           |
|      |                     | - lxml.etree.GlobalParserTLS       |           |
|      |                     | - lxml.etree.getDefaultParser      |           |
|      |                     | - lxml.etree.check_docinfo         |           |
+------+---------------------+------------------------------------+-----------+

B321: ftplib
------------

FTP-related functions are being called. FTP is considered insecure. Use
SSH/SFTP/SCP or some other encrypted protocol.

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Calls                             |  Severity |
+======+=====================+====================================+===========+
| B321 | ftplib              | - ftplib.\*                        | High      |
+------+---------------------+------------------------------------+-----------+

B322: input
-----------

The check for this call has been removed.

The input method in Python 2 will read from standard input, evaluate and
run the resulting string as python source code. This is similar, though in
many ways worse, than using eval. On Python 2, use raw_input instead, input
is safe in Python 3.

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Calls                             |  Severity |
+======+=====================+====================================+===========+
| B322 | input               | - input                            | High      |
+------+---------------------+------------------------------------+-----------+

B323: unverified_context
------------------------

By default, Python will create a secure, verified ssl context for use in such
classes as HTTPSConnection. However, it still allows using an insecure
context via the _create_unverified_context that reverts to the previous
behavior that does not validate certificates or perform hostname checks.

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Calls                             |  Severity |
+======+=====================+====================================+===========+
| B323 | unverified_context  | - ssl._create_unverified_context   | Medium    |
+------+---------------------+------------------------------------+-----------+

B325: tempnam
--------------

Use of os.tempnam() and os.tmpnam() is vulnerable to symlink attacks. Consider
using tmpfile() instead.

For further information:
    https://docs.python.org/2.7/library/os.html#os.tempnam
    https://docs.python.org/3/whatsnew/3.0.html?highlight=tempnam
    https://bugs.python.org/issue17880

+------+---------------------+------------------------------------+-----------+
| ID   |  Name               |  Calls                             |  Severity |
+======+=====================+====================================+===========+
| B325 | tempnam             | - os.tempnam                       | Medium    |
|      |                     | - os.tmpnam                        |           |
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
         'cPickle.Unpickler',
         'dill.loads',
         'dill.load',
         'dill.Unpickler',
         'shelve.open',
         'shelve.DbfilenameShelf'],
        'Pickle and modules that wrap it can be unsafe when used to '
        'deserialize untrusted data, possible security issue.'
    ))

    sets.append(utils.build_conf_dict(
        'marshal', 'B302', ['marshal.load', 'marshal.loads'],
        'Deserialization with the marshal module is possibly dangerous.'
    ))

    sets.append(utils.build_conf_dict(
        'md5', 'B303',
        ['hashlib.md5',
         'hashlib.sha1',
         'Crypto.Hash.MD2.new',
         'Crypto.Hash.MD4.new',
         'Crypto.Hash.MD5.new',
         'Crypto.Hash.SHA.new',
         'Cryptodome.Hash.MD2.new',
         'Cryptodome.Hash.MD4.new',
         'Cryptodome.Hash.MD5.new',
         'Cryptodome.Hash.SHA.new',
         'cryptography.hazmat.primitives.hashes.MD5',
         'cryptography.hazmat.primitives.hashes.SHA1'],
        'Use of insecure MD2, MD4, MD5, or SHA1 hash function.'
    ))

    sets.append(utils.build_conf_dict(
        'ciphers', 'B304',
        ['Crypto.Cipher.ARC2.new',
         'Crypto.Cipher.ARC4.new',
         'Crypto.Cipher.Blowfish.new',
         'Crypto.Cipher.DES.new',
         'Crypto.Cipher.XOR.new',
         'Cryptodome.Cipher.ARC2.new',
         'Cryptodome.Cipher.ARC4.new',
         'Cryptodome.Cipher.Blowfish.new',
         'Cryptodome.Cipher.DES.new',
         'Cryptodome.Cipher.XOR.new',
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
        'mark_safe', 'B308', ['django.utils.safestring.mark_safe'],
        'Use of mark_safe() may expose cross-site scripting '
        'vulnerabilities and should be reviewed.'
    ))

    sets.append(utils.build_conf_dict(
        'httpsconnection', 'B309',
        ['httplib.HTTPSConnection',
         'http.client.HTTPSConnection',
         'six.moves.http_client.HTTPSConnection'],
        'Use of HTTPSConnection on older versions of Python prior to 2.7.9 '
        'and 3.4.3 do not provide security, see '
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
         'random.choices',
         'random.uniform',
         'random.triangular'],
        'Standard pseudo-random generators are not suitable for '
        'security/cryptographic purposes.',
        'LOW'
    ))

    sets.append(utils.build_conf_dict(
        'telnetlib', 'B312', ['telnetlib.*'],
        'Telnet-related functions are being called. Telnet is considered '
        'insecure. Use SSH or some other encrypted protocol.',
        'HIGH'
    ))

    # Most of this is based off of Christian Heimes' work on defusedxml:
    #   https://pypi.org/project/defusedxml/#defusedxml-sax

    xml_msg = ('Using {name} to parse untrusted XML data is known to be '
               'vulnerable to XML attacks. Replace {name} with its '
               'defusedxml equivalent function or make sure '
               'defusedxml.defuse_stdlib() is called')

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
        ('Using {name} to parse untrusted XML data is known to be '
         'vulnerable to XML attacks. Replace {name} with its '
         'defusedxml equivalent function.')
    ))

    # end of XML tests

    sets.append(utils.build_conf_dict(
        'ftplib', 'B321', ['ftplib.*'],
        'FTP-related functions are being called. FTP is considered '
        'insecure. Use SSH/SFTP/SCP or some other encrypted protocol.',
        'HIGH'
    ))

    # skipped B322 as the check for a call to input() has been removed

    sets.append(utils.build_conf_dict(
        'unverified_context', 'B323', ['ssl._create_unverified_context'],
        'By default, Python will create a secure, verified ssl context for '
        'use in such classes as HTTPSConnection. However, it still allows '
        'using an insecure context via the _create_unverified_context that '
        'reverts to the previous behavior that does not validate certificates '
        'or perform hostname checks.'
    ))

    # skipped B324 (used in bandit/plugins/hashlib_new_insecure_functions.py)

    sets.append(utils.build_conf_dict(
        'tempnam', 'B325', ['os.tempnam', 'os.tmpnam'],
        'Use of os.tempnam() and os.tmpnam() is vulnerable to symlink '
        'attacks. Consider using tmpfile() instead.'
    ))

    return {'Call': sets}
