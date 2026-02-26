#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
# Modified by Russ Housley to incorporate Errata 8750.
#
# Copyright (c) 2025-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc2986
from pyasn1_alt_modules import rfc4055
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc9763
from pyasn1_alt_modules import opentypemap


class CertificationRequestTestCase(unittest.TestCase):
    pem_text = """\
MIICbzCCAfUCAQAwcDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAlZBMRAwDgYDVQQH
EwdIZXJuZG9uMRAwDgYDVQQKEwdFeGFtcGxlMQ4wDAYDVQQDEwVBbGljZTEgMB4G
CSqGSIb3DQEJARYRYWxpY2VAZXhhbXBsZS5jb20wdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAAT4zZ8HL+xEDpXWkoWp5xFMTz4u4Ae1nF6zXCYlmsEGD5vPu5hl9hDEjd1U
HRgJIPoy3fJcWWeZ8FHCirICtuMgFisNscG/aTwKyDYOFDuqz/C2jyEwqgWCRyxy
ohuJXtmgggEEMIIBAAYLKoZIhvcNAQkQAjwxgfAwge0wVzBRMQswCQYDVQQGEwJV
UzELMAkGA1UECBMCVkExEDAOBgNVBAcTB0hlcm5kb24xEDAOBgNVBAoTB0V4YW1w
bGUxETAPBgNVBAMTCEJvZ3VzIENBAgICmgIEZ+2IIxYjaHR0cHM6Ly9yZXBvLmV4
YW1wbGUuY29tL215Y2VydC5wN2MDZwAwZAIwYSZ7fwDeTyrhEZISzYNOFBA5DPdM
EmshbzOv3ZLx7wE0+RFxANH4LvZMSEv+qg8JAjAakZoLgRGJTKkROQK+g0/Q4MWG
GWkWjqXBUd3wa77qFKELY8p0B+zhAUNL1kqBB5kwCgYIKoZIzj0EAwMDaAAwZQIx
AIpD3F8fpO4tq0YXdLAvlOJ0b6Fm5mjaqLrJDEzBS4WUfJasvlHtuaMYyygfNHC/
QQIwAPKspeIrY330CGyNnFwT9oecmSfdf+ZTX+UKe6IIvtTNbiDFSWkUPvrBwvzf
Mioc
"""

    def setUp(self):
        self.asn1Spec = rfc2986.CertificationRequest()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        certificateAttributesMap = opentypemap.get('certificateAttributesMap')
        self.assertIn(rfc9763.id_aa_relatedCertRequest, certificateAttributesMap)

        found = False
        for attr in asn1Object['certificationRequestInfo']['attributes']:
            if attr['type'] == rfc9763.id_aa_relatedCertRequest:
                rc, rest = der_decoder(attr['values'][0],
                    asn1Spec=certificateAttributesMap[attr['type']])
                self.assertFalse(rest)
                self.assertTrue(rc.prettyPrint())
                self.assertEqual(attr['values'][0], der_encoder(rc))
                self.assertIn("p7c", rc['locationInfo'])
                found = True

        self.assertTrue(found)

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate,
            asn1Spec=self.asn1Spec, decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        found = False
        for attr in asn1Object['certificationRequestInfo']['attributes']:
            if attr['type'] == rfc9763.id_aa_relatedCertRequest:
                self.assertEqual(0x67ED8823, attr['values'][0]['requestTime'])
                found = True

        self.assertTrue(found)


class CertificationExtensionTestCase(unittest.TestCase):
    pem_text = """\
MIIDWjCCAt+gAwIBAgIJAKWzVCgbsG5cMAoGCCqGSM49BAMDMD8xCzAJBgNVBAYT
AlVTMQswCQYDVQQIDAJWQTEQMA4GA1UEBwwHSGVybmRvbjERMA8GA1UECgwIQm9n
dXMgQ0EwHhcNMjYwMjI2MTYwMjA2WhcNMjcwMjI2MTYwMjA2WjBOMQswCQYDVQQG
EwJVUzELMAkGA1UECBMCVkExEDAOBgNVBAcTB0hlcm5kb24xEDAOBgNVBAoTB0V4
YW1wbGUxDjAMBgNVBAMTBUtlaXRoMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAErg7y
rZBUSfy3PIIjWV1+A/UOuVYyp3jTIKnaayr2HsKA+Go46023Hgm6fgZJC9YfGXRj
6qjerTOkLzuKNYBmJVzfdz6abYMdHGzzJKrTscmQsLrVGn+r5A0c1Bz+Socco4IB
ljCCAZIwHQYDVR0OBBYEFNGhVu4MQu5yVBtg7oXFoxu4dYfvMG8GA1UdIwRoMGaA
FPI12zQE2qVV8r1pA5mwYuziFQjBoUOkQTA/MQswCQYDVQQGEwJVUzELMAkGA1UE
CAwCVkExEDAOBgNVBAcMB0hlcm5kb24xETAPBgNVBAoMCEJvZ3VzIENBggkA6JHW
BpFPzvIwDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCBsAwHAYDVR0RBBUwE4ERa2Vp
dGhAZXhhbXBsZS5jb20wNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRw
Oi8vb2NzcC5leGFtcGxlLmNvbS8wTQYIKwYBBQUHASQEQTA/MAsGCWCGSAFlAwQC
AgQwL+Yu8NtMbhUzfzN/O9f0imarUq3aNBeFcTb+/kgJ2q7Fic8zQgfl3SdsBJJ+
Rd51MEIGCWCGSAGG+EIBDQQ1FjNUaGlzIGNlcnRpZmljYXRlIGNhbm5vdCBiZSB0
cnVzdGVkIGZvciBhbnkgcHVycG9zZS4wCgYIKoZIzj0EAwMDaQAwZgIxAIDoGcpY
3Os3pLRQxyZKTluY4vEB1IzO+YLjMQrP3rklU+pGKSoVpFJzjmZFNNqU7AIxAJSO
ZUOFtABE7D8rgeMDc0FmJJK1kOIa+QbRSzzrIIyXCCOeb2u0pHjsM9eVHM9Neg==
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Certificate()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        certificateExtensionsMap = opentypemap.get('certificateExtensionsMap')
        self.assertIn(rfc9763.id_pe_relatedCert, certificateExtensionsMap)

        found = False
        for extn in asn1Object['tbsCertificate']['extensions']:
            if extn['extnID'] == rfc9763.id_pe_relatedCert:
                extnValue, rest = der_decoder(extn['extnValue'],
                    asn1Spec=certificateExtensionsMap[extn['extnID']])
                self.assertFalse(rest)
                self.assertTrue(extnValue.prettyPrint())
                self.assertEqual(extn['extnValue'], der_encoder(extnValue))
                self.assertEqual(rfc4055.id_sha384,
                    extnValue['hashAlgorithm']['algorithm'])
                found = True

        self.assertTrue(found)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
