#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley
# Copyright (c) 2025-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.type import univ

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc3565
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc5751
from pyasn1_alt_modules import rfc9709
from pyasn1_alt_modules import opentypemap


class CMSEnvelopedDataTestCase(unittest.TestCase):
    cms_pem_text = """\
MIG9BgkqhkiG9w0BBwOgga8wgawCAQIxOqI4AgEEMAwEChjH/HKfZsLuGMQwCwYJ
YIZIAWUDBAEFBBjFfwphC6MYnMBpfSw/MIhGYHGEtxwrgukwawYJKoZIhvcNAQcB
MCwGCyqGSIb3DQEJEAMfMB0GCWCGSAFlAwQBAgQQlixF80pCLxf9qVGK+vl5yIAw
YjvrUVNOpWnJBeQDOGEGMWbpy9S5TI0KUfnR6rPZkOD2SfS8lwNkY/ZeMTwdihFB
"""

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.cms_pem_text)
        ci, rest = der_decoder(substrate, asn1Spec=rfc5652.ContentInfo())
        self.assertFalse(rest)
        self.assertTrue(ci.prettyPrint())
        self.assertEqual(substrate, der_encoder(ci))

        self.assertEqual(rfc5652.id_envelopedData, ci['contentType'])
        ed, rest = der_decoder(ci['content'], asn1Spec=rfc5652.EnvelopedData())
        self.assertFalse(rest)
        self.assertTrue(ed.prettyPrint())
        self.assertEqual(ci['content'], der_encoder(ed))

        self.assertEqual(2, ed['version'])
        self.assertEqual(4, ed['recipientInfos'][0]['kekri']['version'])
        oid = ed['encryptedContentInfo']['contentEncryptionAlgorithm']['algorithm']
        self.assertEqual(rfc9709.id_alg_cek_hkdf_sha256, oid)

        s = ed['encryptedContentInfo']['contentEncryptionAlgorithm']['parameters']
        p, rest = der_decoder(s, asn1Spec=rfc5280.AlgorithmIdentifier())
        self.assertFalse(rest)
        self.assertTrue(p.prettyPrint())
        self.assertEqual(s, der_encoder(p))

        self.assertEqual(p['algorithm'], rfc3565.id_aes128_CBC)

    def testOpenTypes(self):
        algorithmIdentifierMap = opentypemap.get('algorithmIdentifierMap')
        self.assertIn(rfc9709.id_alg_cek_hkdf_sha256, algorithmIdentifierMap)
        self.assertIn(rfc3565.id_aes128_CBC, algorithmIdentifierMap)

        substrate = pem.readBase64fromText(self.cms_pem_text)
        ci, rest = der_decoder(substrate,
            asn1Spec=rfc5652.ContentInfo(), decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(ci.prettyPrint())
        self.assertEqual(substrate, der_encoder(ci))

        ed = ci['content']
        self.assertEqual(2, ed['version'])
        self.assertEqual(4, ed['recipientInfos'][0]['kekri']['version'])
        oid = ed['encryptedContentInfo']['contentEncryptionAlgorithm']['algorithm']
        self.assertEqual(rfc9709.id_alg_cek_hkdf_sha256, oid)
        p = ed['encryptedContentInfo']['contentEncryptionAlgorithm']['parameters']
        self.assertEqual(p['algorithm'], rfc3565.id_aes128_CBC)


class SMimeCapabilitiesTestCase(unittest.TestCase):
    smimecaps_pem_text = """\
MGswCgYIKoUDBwEBBAEwCgYIKoUDBwEBBAIwIAYHKoUDAgINADAVBAgAAAAAAAAA
AAYJKoUDBwECBQEBMCAGByqFAwICDQEwFQQIAAAAAAAAAAAGCSqFAwcBAgUBATAN
BgsqhkiG9w0BCRADHw==
"""

    def setUp(self):
        self.asn1Spec = rfc5751.SMIMECapabilities()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.smimecaps_pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        found = False
        for algid in asn1Object:
            if algid['capabilityID'] == rfc9709.id_alg_cek_hkdf_sha256:
                found = True

        self.assertTrue(found)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
