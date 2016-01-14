# -*- coding:utf-8 -*-
#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
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
=================================
B301: Test for black listed calls
=================================

A number of Python methods and functions are known to have potential security
implications. The blacklist calls plugin test is designed to detect the use of
these methods by scanning code for method calls and checking for their presence
in a configurable blacklist. The scanned calls are fully qualified and
de-aliased prior to checking. To illustrate this, imagine a check for
"evil.thing()" running on the following example code:

.. code-block:: python

    import evil as good

    good.thing()
    thing()

This would generate a warning about calling `evil.thing()` despite the module
being aliased as `good`. It would also not generate a warning on the call to
`thing()` in the local module, as it's fully qualified name will not match.

Each of the provided blacklisted calls can be grouped such that they generate
appropriate warnings (message, severity) and a token `{func}` may be used
in the provided output message, to be replaced with the actual method name.

Due to the nature of the test, confidence is always reported as HIGH

**Config Options:**

.. code-block:: yaml

    blacklist_calls:
        bad_name_sets:
            - pickle:
                qualnames:
                    - pickle.loads
                    - pickle.load
                    - pickle.Unpickler
                    - cPickle.loads
                    - cPickle.load
                    - cPickle.Unpickler
                message: >
                    Pickle library appears to be in use, possible security
                    issue.
            - marshal:
                qualnames: [marshal.load, marshal.loads]
                message: >
                    Deserialization with the {func} is possibly dangerous.
                level: LOW

:Example:

.. code-block:: none

      >> Issue: Pickle library appears to be in use, possible security issue.

        Severity: Medium   Confidence: High
        Location: ./examples/pickle_deserialize.py:20
      19  serialized = cPickle.dumps({(): []})
      20  print(cPickle.loads(serialized))
      21

.. seealso::

 - https://security.openstack.org

.. versionadded:: 0.9.0

"""

import fnmatch

import bandit
from bandit.core import test_properties as test


_cached_blacklist_checks = []
_cached_blacklist_config = None  # FIXME(tkelsey): there is no point in this ..


def _build_conf_dict(name, qualnames, message, level='MEDIUM'):
    return {name: {'message': message, 'qualnames': qualnames, 'level': level}}


def gen_config(name):
    if 'blacklist_calls' == name:
        sets = []

        sets.append(_build_conf_dict(
            'pickle',
            ['pickle.loads',
             'pickle.load',
             'pickle.Unpickler',
             'cPickle.loads',
             'cPickle.load',
             'cPickle.Unpickler'],
            'Pickle library appears to be in use, possible security issue.'
            ))

        sets.append(_build_conf_dict(
            'marshal', ['marshal.load', 'marshal.loads'],
            'Deserialization with the marshal module is possibly dangerous.'
            ))

        sets.append(_build_conf_dict(
            'md5',
            ['hashlib.md5',
             'Crypto.Hash.MD2.new',
             'Crypto.Hash.MD4.new',
             'Crypto.Hash.MD5.new',
             'cryptography.hazmat.primitives.hashes.MD5'],
            'Use of insecure MD2, MD4, or MD5 hash function.'
            ))

        sets.append(_build_conf_dict(
            'ciphers',
            ['Crypto.Cipher.ARC2.new',
             'Crypto.Cipher.ARC4.new',
             'Crypto.Cipher.Blowfish.new',
             'Crypto.Cipher.DES.new',
             'Crypto.Cipher.XOR.new',
             'cryptography.hazmat.primitives.ciphers.algorithms.ARC4',
             'cryptography.hazmat.primitives.ciphers.algorithms.Blowfish',
             'cryptography.hazmat.primitives.ciphers.algorithms.IDEA'],
            'Use of insecure cipher {func}. Replace with a known secure'
            ' cipher such as AES.',
            'HIGH'
            ))

        sets.append(_build_conf_dict(
            'cipher_modes',
            ['cryptography.hazmat.primitives.ciphers.modes.ECB'],
            'Use of insecure cipher mode {func}.'
            ))

        sets.append(_build_conf_dict(
            'mktemp_q', ['tempfile.mktemp'],
            'Use of insecure and deprecated function (mktemp).'
            ))

        sets.append(_build_conf_dict(
            'eval', ['eval'],
            'Use of possibly insecure function - consider using safer '
            'ast.literal_eval.'
            ))

        sets.append(_build_conf_dict(
            'mark_safe', ['mark_safe'],
            'Use of mark_safe() may expose cross-site scripting '
            'vulnerabilities and should be reviewed.'
            ))

        sets.append(_build_conf_dict(
            'httpsconnection',
            ['httplib.HTTPSConnection',
             'http.client.HTTPSConnection',
             'six.moves.http_client.HTTPSConnection'],
            'Use of HTTPSConnection does not provide security, see '
            'https://wiki.openstack.org/wiki/OSSN/OSSN-0033'
            ))

        sets.append(_build_conf_dict(
            'yaml_load', ['yaml.load'],
            'Use of unsafe yaml load. Allows instantiation of arbitrary '
            'objects. Consider yaml.safe_load().'
            ))

        sets.append(_build_conf_dict(
            'urllib_urlopen',
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

        sets.append(_build_conf_dict(
            'random',
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

        sets.append(_build_conf_dict(
            'telnetlib', ['telnetlib.*'],
            'Telnet-related funtions are being called. Telnet is considered '
            'insecure. Use SSH or some other encrypted protocol.',
            'HIGH'
            ))

        # Most of this is based off of Christian Heimes' work on defusedxml:
        #   https://pypi.python.org/pypi/defusedxml/#defusedxml-sax

        xml_msg = ('Using {func} to parse untrusted XML data is known to be '
                   'vulnerable to XML attacks. Replace {func} with its '
                   'defusedxml equivalent function.')

        sets.append(_build_conf_dict(
            'xml_bad_cElementTree',
            ['xml.etree.cElementTree.parse',
             'xml.etree.cElementTree.iterparse',
             'xml.etree.cElementTree.fromstring',
             'xml.etree.cElementTree.XMLParser'],
            xml_msg
            ))

        sets.append(_build_conf_dict(
            'xml_bad_ElementTree',
            ['xml.etree.ElementTree.parse',
             'xml.etree.ElementTree.iterparse',
             'xml.etree.ElementTree.fromstring',
             'xml.etree.ElementTree.XMLParser'],
            xml_msg
            ))

        sets.append(_build_conf_dict(
            'xml_bad_expatreader', ['xml.sax.expatreader.create_parser'],
            xml_msg
            ))

        sets.append(_build_conf_dict(
            'xml_bad_expatbuilder',
            ['xml.dom.expatbuilder.parse',
             'xml.dom.expatbuilder.parseString'],
            xml_msg
            ))

        sets.append(_build_conf_dict(
            'xml_bad_sax',
            ['xml.sax.parse',
             'xml.sax.parseString',
             'xml.sax.make_parser'],
            xml_msg
            ))

        sets.append(_build_conf_dict(
            'xml_bad_minidom',
            ['xml.dom.minidom.parse',
             'xml.dom.minidom.parseString'],
            xml_msg
            ))

        sets.append(_build_conf_dict(
            'xml_bad_pulldom',
            ['xml.dom.pulldom.parse',
             'xml.dom.pulldom.parseString'],
            xml_msg
            ))

        sets.append(_build_conf_dict(
            'xml_bad_etree',
            ['lxml.etree.parse',
             'lxml.etree.fromstring',
             'lxml.etree.RestrictedElement',
             'lxml.etree.GlobalParserTLS',
             'lxml.etree.getDefaultParser',
             'lxml.etree.check_docinfo'],
            xml_msg
            ))

        return {'bad_name_sets': sets}


@test.takes_config
@test.checks('Call')
@test.test_id('B301')
def blacklist_calls(context, config):
    _ensure_cache(config)
    checks = _cached_blacklist_checks

    # for each check, go through and see if it matches all qualifications
    for qualnames, names, message_tpl, level, params in checks:
        confidence = 'HIGH'
        does_match = True
        # item 0=qualnames, 1=names, 2=message, 3=level, 4=params
        if does_match and qualnames:
            # match the qualname - respect wildcards if present
            does_match = any(
                fnmatch.fnmatch(context.call_function_name_qual, qn)
                for qn in qualnames)

        if does_match and names:
            does_match = any(context.call_function_name == n for n in names)

        if does_match and params:
            matched_p = False
            for p in params:
                for arg_num in range(0, context.call_args_count - 1):
                    if p == context.get_call_arg_at_position(arg_num):
                        matched_p = True
            if not matched_p:
                does_match = False

        if does_match:
            message = message_tpl.replace("{func}",
                                          context.call_function_name_qual)

            return bandit.Issue(
                severity=level, confidence=confidence,
                text=message,
                ident=context.call_function_name_qual
            )


def _ensure_cache(config):
    global _cached_blacklist_config
    if _cached_blacklist_checks and config is _cached_blacklist_config:
        return

    _cached_blacklist_config = config
    if config is not None and 'bad_name_sets' in config:
        sets = config['bad_name_sets']
    else:
        sets = []

    # load all the checks from the config file
    for cur_item in sets:
        for blacklist_item in cur_item:
            blacklist_object = cur_item[blacklist_item]
            cur_check = _get_tuple_for_item(blacklist_object)
            # skip bogus checks
            if cur_check:
                _cached_blacklist_checks.append(cur_check)


def _get_tuple_for_item(blacklist_object):
    level_map = {'LOW': bandit.LOW, 'MEDIUM': bandit.MEDIUM,
                 'HIGH': bandit.HIGH}

    # if the item we got passed isn't a dictionary, do nothing with this object
    if not isinstance(blacklist_object, dict):
        return None

    # not all of the fields will be set, so all have default fallbacks
    qualnames = blacklist_object.get('qualnames')
    names = blacklist_object.get('names')
    message = blacklist_object.get('message', '')
    params = blacklist_object.get('params')

    level_name = blacklist_object.get('level', 'MEDIUM').upper()
    level = level_map.get(level_name, 'MEDIUM')

    return (qualnames, names, message, level, params)
