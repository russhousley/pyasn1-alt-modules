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

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc9734


class ServerCertificateTestCase(unittest.TestCase):
    pem_text = """\
MIIC/jCCAoSgAwIBAgIJAKWzVCgbsG5UMAoGCCqGSM49BAMDMD8xCzAJBgNVBAYT
AlVTMQswCQYDVQQIDAJWQTEQMA4GA1UEBwwHSGVybmRvbjERMA8GA1UECgwIQm9n
dXMgQ0EwHhcNMjUwMjA0MTM0MjQxWhcNMjYwMjA0MTM0MjQxWjBNMQswCQYDVQQG
EwJVUzELMAkGA1UECBMCVkExEDAOBgNVBAcTB0hlcm5kb24xHzAdBgNVBAoTFkV4
YW1wbGUgUHJvZHVjdHMsIEluYy4wdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQZzQlk
03nJRPF6+w1NxFELmQ5vJTjTRz3eu03CRtahK4Wnwd4GwbDe8NVHAEG2qTzBXFDu
p6RZugsBdf9GcEZHG42rThYYOzIYzVFnI7tQgA+nTWSWZN6eoU/EXcknhgijggE8
MIIBODAdBgNVHQ4EFgQUkQpUMYcbUesEn5buI03POFnktJgwHwYDVR0jBBgwFoAU
8jXbNATapVXyvWkDmbBi7OIVCMEwCwYDVR0PBAQDAgeAMBMGA1UdJQQMMAoGCCsG
AQUFBwMoMIGPBgNVHREEgYcwgYSgKQYIKwYBBQUHCAegHRYbX3htcHAtY2xpZW50
LmltLmV4YW1wbGUuY29toCkGCCsGAQUFBwgHoB0WG194bXBwLXNlcnZlci5pbS5l
eGFtcGxlLmNvbaAcBggrBgEFBQcIBaAQDA5pbS5leGFtcGxlLmNvbYIOaW0uZXhh
bXBsZS5jb20wQgYJYIZIAYb4QgENBDUWM1RoaXMgY2VydGlmaWNhdGUgY2Fubm90
IGJlIHRydXN0ZWQgZm9yIGFueSBwdXJwb3NlLjAKBggqhkjOPQQDAwNoADBlAjBi
s/JL9qiEZbygneaJxlhBV+GBSQx/XAGy0xHugRSHv8Z1AkigLbyFSTrxIoiu/TYC
MQC9MKLskXXT4AEpswg6uBNi+ImDROxXCBcKntIKbjjx7lnYJiZ/RkTibDReMbtB
lJ0=
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Certificate()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        count = 0
        for extn in asn1Object['tbsCertificate']['extensions']:
            if extn['extnID'] == rfc5280.id_ce_extKeyUsage:
                extnValue, rest = der_decoder(
                    extn['extnValue'], asn1Spec=rfc5280.ExtKeyUsageSyntax())
                self.assertFalse(rest)
                self.assertTrue(extnValue.prettyPrint())
                self.assertEqual(extn['extnValue'], der_encoder(extnValue))

                for eku in extnValue:
                    if eku == rfc9734.id_kp_imUri:
                        count += 1

        self.assertEqual(1, count)

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate,
            asn1Spec=self.asn1Spec, decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        count = 0

        for extn in asn1Object['tbsCertificate']['extensions']:
            if extn['extnID'] == rfc5280.id_ce_extKeyUsage:
                extnValue, rest = der_decoder(extn['extnValue'],
                    asn1Spec=rfc5280.ExtKeyUsageSyntax(),
                    decodeOpenTypes=True)
                self.assertFalse(rest)
                self.assertTrue(extnValue.prettyPrint())
                self.assertEqual(extn['extnValue'], der_encoder(extnValue))

                for eku in extnValue:
                    if eku == rfc9734.id_kp_imUri:
                        count += 1

        self.assertEqual(1, count)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
