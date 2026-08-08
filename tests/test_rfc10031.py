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
from pyasn1.type import univ

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc10031


class MACAddressOtherNameTestCase(unittest.TestCase):
    pem_text = """\
MIICsTCCAjegAwIBAgIJAKWzVCgbsG5eMAoGCCqGSM49BAMDMD8xCzAJBgNVBAYT
AlVTMQswCQYDVQQIDAJWQTEQMA4GA1UEBwwHSGVybmRvbjERMA8GA1UECgwIQm9n
dXMgQ0EwHhcNMjYwMjI4MTYwMzI4WhcNMjcwMjI4MTYwMzI4WjBfMQswCQYDVQQG
EwJVUzELMAkGA1UECBMCVkExEDAOBgNVBAcTB0hlcm5kb24xHzAdBgNVBAoTFkV4
YW1wbGUgUHJvZHVjdHMsIEluYy4xEDAOBgNVBAMTB2V4MTIzNDUwdjAQBgcqhkjO
PQIBBgUrgQQAIgNiAATsuN7eCVLapiXnHo31M6UPgJufN8V4lB9sNoJre97ESLAT
Rqm4A/7gvl+o6xh5kL3vSI1b7Pc91SwbOQoMLZwJXLycjFDeZaE1AO9q9PeLPk4Z
LBrUaNJdEVsafbH1CM2jgd4wgdswQgYJYIZIAYb4QgENBDUWM1RoaXMgY2VydGlm
aWNhdGUgY2Fubm90IGJlIHRydXN0ZWQgZm9yIGFueSBwdXJwb3NlLjAdBgNVHQ4E
FgQU9NA3WRcQzlF3iE29AvkfID6jY2gwHwYDVR0jBBgwFoAU8jXbNATapVXyvWkD
mbBi7OIVCMEwDgYDVR0PAQH/BAQDAgeAMB8GA1UdEQQYMBagFAYIKwYBBQUHCAyg
CAQGACSYexkCMCQGA1UdCQQdMBswGQYJYIZIAWUCAQVFMQwGCisGAQQBgaxgMBgw
CgYIKoZIzj0EAwMDaAAwZQIxANS1pRH0OEarCztZEfGxmxX52walCyRu0/3WXGjw
hhVqnQEQUuU2ItpxFFiusw4PYwIwH02LK5d7KeMkmMq9rPqhDmLMq/Mvy5o6zWzw
aE9Xke7UhMI6kM8dtbeZyi1YBMB0
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Certificate()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        macaddr_found = False
        for extn in asn1Object['tbsCertificate']['extensions']:
            if extn['extnID'] == rfc5280.id_ce_subjectAltName:
                san, rest = der_decoder(
                    extn['extnValue'], asn1Spec=rfc5280.SubjectAltName())
                self.assertFalse(rest)
                self.assertTrue(san.prettyPrint())
                self.assertEqual(extn['extnValue'], der_encoder(san))
                self.assertEqual(1, len(san))
                self.assertEqual(rfc10031.id_on_MACAddress,
                    san[0]['otherName']['type-id'])

                macaddr, rest = der_decoder(san[0]['otherName']['value'],
                    asn1Spec=rfc10031.MACAddress())
                self.assertFalse(rest)
                self.assertTrue(macaddr.prettyPrint())
                self.assertEqual(san[0]['otherName']['value'],
                    der_encoder(macaddr))
                self.assertEqual(6, len(macaddr.asOctets()))
                self.assertEqual('0x0024987b1902', macaddr.prettyPrint())
                macaddr_found = True

        self.assertTrue(macaddr_found)

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(
            substrate, asn1Spec=self.asn1Spec, decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        macaddr_found = False
        for extn in asn1Object['tbsCertificate']['extensions']:
            if extn['extnID'] == rfc5280.id_ce_subjectAltName:
                san, rest = der_decoder(extn['extnValue'],
                    asn1Spec=rfc5280.SubjectAltName(), decodeOpenTypes=True)
                self.assertFalse(rest)
                self.assertTrue(san.prettyPrint())
                self.assertEqual(extn['extnValue'], der_encoder(san))
                self.assertEqual(1, len(san))
                self.assertEqual(rfc10031.id_on_MACAddress,
                    san[0]['otherName']['type-id'])
                self.assertEqual(6,
                    len(san[0]['otherName']['value'].asOctets()))
                self.assertEqual('0x0024987b1902',
                    san[0]['otherName']['value'].prettyPrint())
                macaddr_found = True

        self.assertTrue(macaddr_found)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
