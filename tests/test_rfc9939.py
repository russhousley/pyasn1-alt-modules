#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley
# Copyright (c) 2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc8410
from pyasn1_alt_modules import rfc9939
from pyasn1_alt_modules import opentypemap


class OnePrivateKeyTestCase(unittest.TestCase):
    pem_text = """\
MIGDBgsqhkiG9w0BCRABNKB0MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp
+K06/nwoy/HU++CXqI9EdVhCoB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hh
aXJzgSEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
"""

    def setUp(self):
        self.asn1Spec = rfc5652.ContentInfo()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertTrue(
            rfc9939.id_ct_privateKeyInfo, asn1Object['contentType'])
        pki, rest = der_decoder(
            asn1Object['content'], asn1Spec=rfc9939.PrivateKeyInfo())
        self.assertFalse(rest)
        self.assertTrue(pki.prettyPrint())

        self.assertEqual(
            rfc8410.id_Ed25519, pki['privateKeyAlgorithm']['algorithm'])
        self.assertTrue(pki['privateKey'].isValue)
        self.assertEqual(
            "0x0420d4ee", pki['privateKey'].prettyPrint()[0:10])
        self.assertTrue(pki['publicKey'].isValue)
        self.assertEqual(
            "1164575857", pki['publicKey'].prettyPrint()[0:10])


class ContentTypesMapTestCase(unittest.TestCase):

    def testOpenTypes(self):
        cmsContentTypesMap = opentypemap.get('cmsContentTypesMap')
        self.assertIn(rfc9939.id_ct_privateKeyInfo, cmsContentTypesMap)
        self.assertIn(rfc9939.id_ct_encrPrivateKeyInfo, cmsContentTypesMap)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
