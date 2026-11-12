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
from pyasn1_alt_modules import rfc6960
from pyasn1_alt_modules import rfc8226
from pyasn1_alt_modules import rfc10089
from pyasn1_alt_modules import opentypemap


class STIROCSPRequestTestCase(unittest.TestCase):
    ocsp_req_pem_text = """\
MIGnMIGkMH0wezBZMA0GCWCGSAFlAwQCAQUABCCdRGd1m8TsykXHpoWP+cRdO4E2
6WxG1ImeNnW+W+QcUgQg1OQi1Ss3Hf9J6kAZpKnfmm77CUVHUbmhh7NioCytJW4C
BDXe9M+gHjAcMBoGCSsGAQUFBzABCgQNFgsxMjAyNTU1MTIxMqIjMCEwHwYJKwYB
BQUHMAECBBIEEGN0k6Ihb0QokYQs01/+t0A=
"""

    def setUp(self):
        self.asn1Spec = rfc6960.OCSPRequest()

    def testDerCodec(self):
        certificateExtensionsMap = opentypemap.get('certificateExtensionsMap')

        substrate = pem.readBase64fromText(self.ocsp_req_pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))
        self.assertEqual(0, asn1Object['tbsRequest']['version'])

        found_nonce = False
        for extn in asn1Object['tbsRequest']['requestExtensions']:
            self.assertIn(extn['extnID'], certificateExtensionsMap)

            ev, rest = der_decoder(extn['extnValue'],
                asn1Spec=certificateExtensionsMap[extn['extnID']])
            self.assertFalse(rest)
            self.assertTrue(ev.prettyPrint())
            self.assertEqual(extn['extnValue'], der_encoder(ev))

            if extn['extnID'] == rfc6960.id_pkix_ocsp_nonce:
                self.assertEqual('637493a221', ev.asOctets().hex()[:10])
                found_nonce = True

        found_stir_tn = False
        first_request = asn1Object['tbsRequest']['requestList'][0]
        for extn in first_request['singleRequestExtensions']:
            self.assertIn(extn['extnID'], certificateExtensionsMap)

            ev, rest = der_decoder(extn['extnValue'],
                asn1Spec=certificateExtensionsMap[extn['extnID']])
            self.assertFalse(rest)
            self.assertTrue(ev.prettyPrint())
            self.assertEqual(extn['extnValue'], der_encoder(ev))

            if extn['extnID'] == rfc10089.id_pkix_ocsp_stir_tn:
                self.assertEqual(rfc8226.TelephoneNumber('12025551212'), ev)
                found_stir_tn = True

        self.assertTrue(found_nonce and found_stir_tn)


class STIROCSPResponseTestCase(unittest.TestCase):
    ocsp_resp_pem_text = """\
MIIDbQoBAKCCA2YwggNiBgkrBgEFBQcwAQEEggNTMIIDTzCB9aIWBBQ8T5f++IIw
3WyQrjVceyyHwm0EuxgPMjAyNDA2MTgwNTA5MDBaMIGkMIGhMFkwDQYJYIZIAWUD
BAIBBQAEIJ1EZ3WbxOzKRcemhY/5xF07gTbpbEbUiZ42db5b5BxSBCDU5CLVKzcd
/0nqQBmkqd+abvsJRUdRuaGHs2KgLK0lbgIENd70z4IAGA8yMDI0MDYxODA4MDAw
MFqgERgPMjAyNDA2MjAwODAwMDBaoR4wHDAaBgkrBgEFBQcwAQoEDRYLMTIwMjU1
NTEyMTKhIzAhMB8GCSsGAQUFBzABAgQSBBBjdJOiIW9EKJGELNNf/rdAMAoGCCqG
SM49BAMCA0gAMEUCIQCsV623IDsTwo1upzfTgR0D4HPI3906jgZYSKbq1dR18wIg
IX6iW1BOReyZqx5R3NE1MDag6aJeMILyxwxrgm127BWgggH9MIIB+TCCAfUwggGb
oAMCAQICFH90o/wDbOIUeFxZYU5vjfJMR6hzMAoGCCqGSM49BAMCMDcxCzAJBgNV
BAYTAlVTMRMwEQYDVQQKEwpFeGFtcGxlIENBMRMwEQYDVQQDEwpjYS5leGFtcGxl
MB4XDTI0MDMyNDA3Mzg1NFoXDTI1MDMyNDA3Mzg1NFowNzELMAkGA1UEBhMCVVMx
EzARBgNVBAoTCkV4YW1wbGUgQ0ExEzARBgNVBAMTCmNhLmV4YW1wbGUwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAASYMgUfqSdYEO6RxLSaas3wbW5Qpul5g5gqOuwP
ZoKsWqCyHiiYE9ZNY5N0jYgqFiDvpmJgSbMWAITWLcAdUUp8o4GEMIGBMAwGA1Ud
EwEB/wQCMAAwCwYDVR0PBAQDAgeAMB0GA1UdDgQWBBQ8T5f++IIw3WyQrjVceyyH
wm0EuzAfBgNVHSMEGDAWgBQuz95oyHOEmDVVEJcTmKw3WepikDATBgNVHSUEDDAK
BggrBgEFBQcDCTAPBgkrBgEFBQcwAQUEAgUAMAoGCCqGSM49BAMCA0gAMEUCIGGq
VQ+e5BXYumtngE6GWVM6LN35PW2cKCcWQWB0lf7zAiEA8YXYz4joTWKfLwmL/G9q
IH59+KaeWOQ7DDfDgGQi2vI=
"""

    def setUp(self):
        self.asn1Spec = rfc6960.OCSPResponse()

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

        found = False
        for extn in resp['tbsResponseData']['responses'][0]['singleExtensions']:
            self.assertIn(extn['extnID'], certificateExtensionsMap)

            ev, rest = der_decoder(extn['extnValue'],
                asn1Spec=certificateExtensionsMap[extn['extnID']])
            self.assertFalse(rest)
            self.assertTrue(ev.prettyPrint())
            self.assertEqual(extn['extnValue'], der_encoder(ev))

            if extn['extnID'] == rfc10089.id_pkix_ocsp_stir_tn:
                self.assertEqual(rfc8226.TelephoneNumber('12025551212'), ev)
                found = True

        self.assertTrue(found)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
