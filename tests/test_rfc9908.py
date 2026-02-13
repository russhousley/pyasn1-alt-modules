#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley
# Copyright (c) 2025-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.type import univ

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc2985
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc5480
from pyasn1_alt_modules import rfc7030
from pyasn1_alt_modules import rfc8994
from pyasn1_alt_modules import rfc9908


class RFC9908Section5_1TestCase(unittest.TestCase):
    pem_text = """\
MGgwZgYJKoZIhvcNAQkOMVkwVzBVBgNVHREBAf8ESzBJoEcG
CCsGAQUFBwgKoDsWOXJmYzg5OTQrZmQ3MzlmYzIzYzM0NDAx
MTIyMzM0NDU1MDAwMDAwMDArQGFjcC5leGFtcGxlLmNvbQ==
"""

    def setUp(self):
        self.asn1Spec = rfc7030.CsrAttrs()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        attr = asn1Object[0]['attribute']
        self.assertEqual(rfc2985.pkcs_9_at_extensionRequest, attr['attrType'])

        extns, rest = der_decoder(attr['attrValues'][0],
            asn1Spec=rfc9908.ExtensionTemplates())
        self.assertFalse(rest)
        self.assertTrue(extns.prettyPrint())
        self.assertEqual(attr['attrValues'][0], der_encoder(extns))

        extn = extns[0]
        self.assertEqual(rfc5280.id_ce_subjectAltName, extn['extnID'])
        san, rest = der_decoder(extn['extnValue'],
            asn1Spec=rfc5280.SubjectAltName())
        self.assertFalse(rest)
        self.assertTrue(san.prettyPrint())
        self.assertEqual(extn['extnValue'], der_encoder(san))
        
        self.assertEqual(1, len(san))
        self.assertEqual(rfc8994.id_on_AcpNodeName,
            san[0]['otherName']['type-id'])
        acpnn, rest = der_decoder(san[0]['otherName']['value'],
            asn1Spec=rfc8994.AcpNodeName())
        self.assertFalse(rest)
        self.assertTrue(acpnn.prettyPrint())
        self.assertEqual(san[0]['otherName']['value'], der_encoder(acpnn))

        self.assertIn('acp.example.com', acpnn)


class RFC9908Section5_2TestCase(unittest.TestCase):
    pem_text = """\
MDIGCSqGSIb3DQEJBzASBgcqhkjOPQIBMQcGBSuBBAAiBgcr
BgEBAQEWBggqhkjOPQQDAw==
"""

    def setUp(self):
        self.asn1Spec = rfc7030.CsrAttrs()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        attr_count = 0
        oid_count = 0
        ecc_count = 0
        for entry in asn1Object:
            if entry.getName() == 'oid':
                oid_count += 1
            if entry.getName() == 'attribute':
                attr_count += 1
                if entry['attribute']['attrType'] == rfc5480.id_ecPublicKey:
                    p, rest = der_decoder(entry['attribute']['attrValues'][0],
                        asn1Spec=rfc5480.ECParameters())
                    self.assertFalse(rest)
                    self.assertTrue(p.prettyPrint())
                    self.assertEqual(entry['attribute']['attrValues'][0],
                        der_encoder(p))
                    self.assertEqual(rfc5480.secp384r1, p) 
                    ecc_count +=1

        self.assertEqual(1, attr_count)
        self.assertEqual(3, oid_count)
        self.assertEqual(1, ecc_count)


class RFC9908Section5_3TestCase(unittest.TestCase):
    pem_text = """\
MEUGCSqGSIb3DQEJBzASBgcqhkjOPQIBMQcGBSuBBAAjBgkq
hkiG9w0BCRQGCgmSJomT8ixkAQUGA1UEBQYIKoZIzj0EAwQ=
"""

    def setUp(self):
        self.asn1Spec = rfc7030.CsrAttrs()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        attr_count = 0
        oid_count = 0
        ecc_count = 0
        for entry in asn1Object:
            if entry.getName() == 'oid':
                oid_count += 1
            if entry.getName() == 'attribute':
                attr_count += 1
                if entry['attribute']['attrType'] == rfc5480.id_ecPublicKey:
                    p, rest = der_decoder(entry['attribute']['attrValues'][0],
                        asn1Spec=rfc5480.ECParameters())
                    self.assertFalse(rest)
                    self.assertTrue(p.prettyPrint())
                    self.assertEqual(entry['attribute']['attrValues'][0],
                        der_encoder(p))
                    self.assertEqual(rfc5480.secp521r1, p) 
                    ecc_count +=1

        self.assertEqual(1, attr_count)
        self.assertEqual(5, oid_count)
        self.assertEqual(1, ecc_count)


class RFC9908Section5_4TestCase(unittest.TestCase):
    pem_text = """\
MCkGCSqGSIb3DQEJBzARBgkqhkiG9w0BAQExBAICEAAGCSqG
SIb3DQEBCw==
"""

    def setUp(self):
        self.asn1Spec = rfc7030.CsrAttrs()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        attr_count = 0
        oid_count = 0
        rsa_count = 0
        for entry in asn1Object:
            if entry.getName() == 'oid':
                oid_count += 1
            if entry.getName() == 'attribute':
                attr_count += 1
                if entry['attribute']['attrType'] == rfc5480.rsaEncryption:
                    value, rest = der_decoder(entry['attribute']['attrValues'][0],
                        asn1Spec=univ.Integer())
                    self.assertFalse(rest)
                    self.assertTrue(value.prettyPrint())
                    self.assertEqual(entry['attribute']['attrValues'][0],
                        der_encoder(value))
                    self.assertEqual(4096, value) 
                    rsa_count +=1

        self.assertEqual(1, attr_count)
        self.assertEqual(2, oid_count)
        self.assertEqual(1, rsa_count)


class RFC9908Section5_5TestCase(unittest.TestCase):
    pem_text = """\
MC4GCSqGSIb3DQEJBzASBgcqhkjOPQIBMQcGBSuBBAAiBgNV
BAUGCCqGSM49BAMD
"""

    def setUp(self):
        self.asn1Spec = rfc7030.CsrAttrs()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        attr_count = 0
        oid_count = 0
        ecc_count = 0
        for entry in asn1Object:
            if entry.getName() == 'oid':
                oid_count += 1
            if entry.getName() == 'attribute':
                attr_count += 1
                if entry['attribute']['attrType'] == rfc5480.id_ecPublicKey:
                    p, rest = der_decoder(entry['attribute']['attrValues'][0],
                        asn1Spec=rfc5480.ECParameters())
                    self.assertFalse(rest)
                    self.assertTrue(p.prettyPrint())
                    self.assertEqual(entry['attribute']['attrValues'][0],
                        der_encoder(p))
                    self.assertEqual(rfc5480.secp384r1, p['namedCurve']) 
                    ecc_count +=1

        self.assertEqual(1, attr_count)
        self.assertEqual(3, oid_count)
        self.assertEqual(1, ecc_count)


class RFC9908Section5_6TestCase(unittest.TestCase):
    pem_text = """\
MEUGCSqGSIb3DQEJBzASBgcqhkjOPQIBMQcGBSuBBAAjBgkq
hkiG9w0BCRQGCgmSJomT8ixkAQUGA1UEBQYIKoZIzj0EAwQ=
"""

    def setUp(self):
        self.asn1Spec = rfc7030.CsrAttrs()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        attr_count = 0
        oid_count = 0
        ecc_count = 0
        for entry in asn1Object:
            if entry.getName() == 'oid':
                oid_count += 1
            if entry.getName() == 'attribute':
                attr_count += 1
                if entry['attribute']['attrType'] == rfc5480.id_ecPublicKey:
                    p, rest = der_decoder(entry['attribute']['attrValues'][0],
                        asn1Spec=rfc5480.ECParameters())
                    self.assertFalse(rest)
                    self.assertTrue(p.prettyPrint())
                    self.assertEqual(entry['attribute']['attrValues'][0],
                        der_encoder(p))
                    self.assertEqual(rfc5480.secp521r1, p['namedCurve']) 
                    ecc_count +=1

        self.assertEqual(1, attr_count)
        self.assertEqual(5, oid_count)
        self.assertEqual(1, ecc_count)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
