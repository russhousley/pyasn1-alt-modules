#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley
# Copyright (c) 2024-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.type import error
from pyasn1.type import univ

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc4055
from pyasn1_alt_modules import rfc9654
from pyasn1_alt_modules import opentypemap


class OCSPRequestTestCase(unittest.TestCase):
    ocsp_req_pem_text = """\
MIGHMIGEMF0wWzBZMA0GCWCGSAFlAwQCAQUABCA6mUZ3VoBzpwe/3lAYY0XkzWE0
2wheuqHRBCXwO28I6gQgR0psowHyPcn39weHBOHH9fyW5xZ19u2ILnq2XD9YRUMC
BAGq8A2iIzAhMB8GCSsGAQUFBzABAgQSBBBjdJOiIW9EKJGELNNf/rdA
"""

    def setUp(self):
        self.asn1Spec = rfc9654.OCSPRequest()

    def testDerCodec(self):
        certificateExtensionsMap = opentypemap.get('certificateExtensionsMap')

        substrate = pem.readBase64fromText(self.ocsp_req_pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))
        self.assertEqual(0, asn1Object['tbsRequest']['version'])

        count = 0
        for extn in asn1Object['tbsRequest']['requestExtensions']:
            self.assertIn(extn['extnID'], certificateExtensionsMap)

            ev, rest = der_decoder(extn['extnValue'],
                asn1Spec=certificateExtensionsMap[extn['extnID']])
            self.assertFalse(rest)
            self.assertTrue(ev.prettyPrint())
            self.assertEqual(extn['extnValue'], der_encoder(ev))
            count += 1

        self.assertEqual(1, count)

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.ocsp_req_pem_text)
        asn1Object, rest = der_decoder(
            substrate, asn1Spec=self.asn1Spec, decodeOpenTypes=True)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))
        self.assertEqual(0, asn1Object['tbsRequest']['version'])

        for req in asn1Object['tbsRequest']['requestList']:
            ha = req['reqCert']['hashAlgorithm']
            self.assertEqual(rfc4055.id_sha256, ha['algorithm'])
            self.assertEqual(univ.Null(""), ha['parameters'])


class OCSPResponseTestCase(unittest.TestCase):
    ocsp_resp_pem_text = """\
MIIDnwoBAKCCA5gwggOUBgkrBgEFBQcwAQEEggOFMIIDgTCBsKIWBBQK46D+ndQl
dpi163Lrygznvz318RgPMjAyNDA0MDIxMjM3NDdaMIGEMIGBMFkwDQYJYIZIAWUD
BAIBBQAEIDqZRndWgHOnB7/eUBhjReTNYTTbCF66odEEJfA7bwjqBCBHSmyjAfI9
yff3B4cE4cf1/JbnFnX27YguerZcP1hFQwIEAarwDYAAGA8yMDI0MDQwMzEyMzc0
N1qgERgPMjAyNDA0MTAxMjM3NDdaMAoGCCqGSM49BAMDA2kAMGYCMQDRmVmiIb4D
m9yEXiv2XtoeQi6ftpjLmlBqqRIi+3htfF/OyjdHnFuh38cQKYqqrWYCMQDKiPct
Vu7SQs587d2ZBEHQH20j5AFiGGsbI1b3+C9ZK6NIzgD6DnWlDwpSfilEarOgggJT
MIICTzCCAkswggGuoAMCAQICAQEwCgYIKoZIzj0EAwQwODELMAkGA1UEBhMCWFgx
FDASBgNVBAoMC0NlcnRzICdyIFVzMRMwEQYDVQQDDApJc3N1aW5nIENBMB4XDTI0
MDQwMjEyMzc0N1oXDTI1MDQwMjEyMzc0N1owPDELMAkGA1UEBhMCWFgxFDASBgNV
BAoMC0NlcnRzICdyIFVzMRcwFQYDVQQDDA5PQ1NQIFJlc3BvbmRlcjB2MBAGByqG
SM49AgEGBSuBBAAiA2IABFsJAbiFIyluuRnVD/oanLN0vE1AlYYoK/7KEbHZWtu1
RzSvVwv4K3IozyJrz0wl3bz+Oxo605Qw7/dj4daNLhUdkXILd5W1jaazRjlhOo+5
tajaSMZ0cRf5kZ6EJPN+yKOBhzCBhDAdBgNVHQ4EFgQUCuOg/p3UJXaYtety68oM
57899fEwHwYDVR0jBBgwFoAUjsIUCWB26pA46TmuG21SxBd9n74wDAYDVR0TAQH/
BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwkwDwYJKwYB
BQUHMAEFBAIFADAKBggqhkjOPQQDBAOBigAwgYYCQRQqjNYKbGXHdGXfEVvB//i+
DiG02hraU9kGNKXeiQcPdZRajQsY/hdZPVyaykkAFVQGv29yWmTrEax+r4oZTtzG
AkFJCwtJpi7m00Qx9r/ugNWsnCFSiKUdxuvj7mg9lJtz0hexRJZKFODWJG5dUh//
Bc2w8vywgYYoduXu4QLcoP17CA==
"""

    def setUp(self):
        self.asn1Spec = rfc9654.OCSPResponse()

    def testDerCodec(self):
        ocspResponseMap = opentypemap.get('ocspResponseMap')
        certificateExtensionsMap = opentypemap.get('certificateExtensionsMap')

        substrate = pem.readBase64fromText(self.ocsp_resp_pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))
        self.assertEqual(0, asn1Object['responseStatus'])

        rb = asn1Object['responseBytes']
        self.assertIn(rb['responseType'], ocspResponseMap)

        resp, rest = der_decoder(rb['response'],
            asn1Spec=ocspResponseMap[rb['responseType']])
        self.assertFalse(rest)
        self.assertTrue(resp.prettyPrint())
        self.assertEqual(rb['response'], der_encoder(resp))
        self.assertEqual(0, resp['tbsResponseData']['version'])
        self.assertEqual(0, len(resp['tbsResponseData']['responseExtensions']))

    def testOpenTypes(self):
        ocspResponseMap = opentypemap.get('ocspResponseMap')

        substrate = pem.readBase64fromText(self.ocsp_resp_pem_text)
        asn1Object, rest = der_decoder(substrate,
            asn1Spec=self.asn1Spec, decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))
        self.assertEqual(0, asn1Object['responseStatus'])

        rb = asn1Object['responseBytes']
        self.assertIn(rb['responseType'], ocspResponseMap)

        resp, rest = der_decoder(rb['response'],
            asn1Spec=ocspResponseMap[rb['responseType']], decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(resp.prettyPrint())
        self.assertEqual(rb['response'], der_encoder(resp))

        self.assertEqual(0, resp['tbsResponseData']['version'])
        self.assertTrue(resp['tbsResponseData']['responderID']['byKey'].hasValue())

        for r in resp['tbsResponseData']['responses']:
            ha = r['certID']['hashAlgorithm']
            self.assertEqual(rfc4055.id_sha256, ha['algorithm'])
            self.assertEqual(univ.Null(""), ha['parameters'])


class BadNonceSizeTestCase(unittest.TestCase):
    empty_nonce_extn_value_pem_text = "BAA="
    big_nonce_extn_value_pem_text = """\
BIGgtY7oVxpr39n/QprRa5bpcQIvbV/g93PpSPiRrhaL6g44WCC4TnY88ZUjS7fE
LcgfSW5gA/oakaDA2BCsXodVAF+DRoIGZVjPpn50Yf4ODJ3mWp3uyuF51dVILqiX
XXyGcd+/99CTkvg2eBx1GFM8HmwuP2boVIJPqijeqEH/DQWlJH7D56IVmNcfG6CB
d1ZMFfmbH+xL0vlSalpnQ2DEKA==
"""

    def setUp(self):
        self.asn1Spec = rfc9654.Nonce()

    def testEmptyNonceValueConstraintError(self):
        substrate = pem.readBase64fromText(self.empty_nonce_extn_value_pem_text)
        with self.assertRaises(error.ValueConstraintError):
            ev, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)

    def testBigNonceValueConstraintError(self):
        substrate = pem.readBase64fromText(self.big_nonce_extn_value_pem_text)
        with self.assertRaises(error.ValueConstraintError):
            ev, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
