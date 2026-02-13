#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley
# Copyright (c) 2023-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5751
from pyasn1_alt_modules import opentypemap


class CMPAlgorithmsTestCase(unittest.TestCase):
    pem_text = """\
MIIBoDALBglghkgBZQMEAgQwCwYJYIZIAWUDBAIBMAsGCWCGSAFlAwQCAjALBglg
hkgBZQMEAgMwCwYJYIZIAWUDBAILMAsGCWCGSAFlAwQCDDAKBggrBgEFBQcGHjAK
BggrBgEFBQcGHzAKBggrBgEFBQcGIDAKBggrBgEFBQcGITAFBgMrZXAwBQYDK2Vx
MBoGCyqGSIb3DQEJEAMFMAsGCWCGSAFlAwQBLTAVBgYrgQQBCwMwCwYJYIZIAWUD
BAEtMBUGBiuBBAEOATALBglghkgBZQMEAS0wFQYGK4EEAQ8DMAsGCWCGSAFlAwQB
LTAFBgMrZW4wBQYDK2VvMAsGCSqGSIb3DQEBBzALBglghkgBZQMEAS0wCwYJKoZI
hvcNAQUMMAsGCWCGSAFlAwQBKjALBgkqhkiG9n0HQg0wCwYJKoZIhvcNAQUOMAoG
CCqGSIb3DQIIMAoGCCqGSIb3DQIJMAoGCCqGSIb3DQIKMAoGCCqGSIb3DQILMAsG
CWCGSAFlAwQBMTALBglghkgBZQMEAhMwCwYJYIZIAWUDBAIU
"""

    def setUp(self):
        self.asn1Spec = rfc5751.SMIMECapabilities()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        algorithmIdentifierMap = opentypemap.get('algorithmIdentifierMap')
        smimeCapabilityMap = opentypemap.get('smimeCapabilityMap')

        count = 0
        for algid in asn1Object:
            count += 1
            if algid['parameters'].hasValue():
                self.assertIn(algid['capabilityID'], algorithmIdentifierMap)
                self.assertIn(algid['capabilityID'], smimeCapabilityMap)

        self.assertEqual(31, count)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
