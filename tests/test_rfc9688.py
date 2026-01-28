#
# This file is part of pyasn1-alt-modules software.
#
# Copyright (c) 2019-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc5751
from pyasn1_alt_modules import rfc9688
from pyasn1_alt_modules import opentypemap


class SMIMECapabilitiesTestCase(unittest.TestCase):
    pem_text = """\
MIIBLjALBglghkgBZQMEAgcwCwYJYIZIAWUDBAIIMAsGCWCGSAFlAwQCCTALBglg
hkgBZQMEAgowDQYJYIZIAWUDBAMNBQAwDQYJYIZIAWUDBAMOBQAwDQYJYIZIAWUD
BAMPBQAwDQYJYIZIAWUDBAMQBQAwCwYJYIZIAWUDBAMJMAsGCWCGSAFlAwQDCjAL
BglghkgBZQMEAwswCwYJYIZIAWUDBAMMMAsGCWCGSAFlAwQCDTALBglghkgBZQME
Ag4wCwYJYIZIAWUDBAIPMAsGCWCGSAFlAwQCEDANBgsqhkiG9w0BCRADIDANBgsq
hkiG9w0BCRADITANBgsqhkiG9w0BCRADIjANBgsqhkiG9w0BCRADIzALBglghkgB
ZQMEAhUwCwYJYIZIAWUDBAIW
"""

    def setUp(self):
        self.asn1Spec = rfc5751.SMIMECapabilities()

    def testDerCodec(self):
        algorithmIdentifierMap = opentypemap.get('algorithmIdentifierMap')
        smimeCapabilityMap = opentypemap.get('smimeCapabilityMap')

        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))
        
        found = False
        for algid in asn1Object:
            if algid['parameters'].hasValue():
                self.assertIn(algid['capabilityID'], algorithmIdentifierMap)
                self.assertIn(algid['capabilityID'], smimeCapabilityMap)
                found = True

        self.assertTrue(found)


class KDF3AlgorithmIdentifierTestCase(unittest.TestCase):
    pem_text = "MBkGCiuBBRCGSAksAQIwCwYJYIZIAWUDBAII"

    def setUp(self):
        self.asn1Spec = rfc5280.AlgorithmIdentifier()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual(rfc9688.id_kdf_kdf3, asn1Object['algorithm'])

        param, rest = der_decoder(asn1Object['parameters'], asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(param.prettyPrint())
        self.assertEqual(asn1Object['parameters'], der_encoder(param))
    
        self.assertEqual(rfc9688.id_sha3_256, param['algorithm'])


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
