#
# This file is part of pyasn1-alt-modules software.
#
# Copyright (c) 2025-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.type import char
from pyasn1.type import univ

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc2986
from pyasn1_alt_modules import rfc9883
from pyasn1_alt_modules import opentypemap


class PrivateKeyPossessionStatementTestCase(unittest.TestCase):
    pem_text = """\
MIIEMTCCA7gCAQAwPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAlZBMRAwDgYDVQQH
EwdIZXJuZG9uMQ4wDAYDVQQDEwVBbGljZTB0MA4GBSuBBAEMBgUrgQQAIgNiAAQB
RyQTH+cq1s5F94uFqFe7l1LqGdEC8Tm+e5VYBCfKAC8MJySQMj1GixEEXL+1Wjtg
23XvnJouCDoxSpDCSMqf3kvp5+naM37uxa3ZYgD6DPY3me5EZvyZPvSRJTFl/Bag
ggL9MGcGCSqGSIb3DQEJDjFaMFgwDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCAwgw
IgYDVR0RBBswGYEXYWxpY2VAZW1haWwuZXhhbXBsZS5jb20wFwYDVR0gBBAwDjAM
BgpghkgBZQMCATAwMIICkAYKKwYBBAGBrGACATGCAoAwggJ8ME8wNzELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkV4YW1wbGUgQ0ExEzARBgNVBAMTCmNhLmV4YW1wbGUC
FH90o/wDbOIUeFxZYU5vjfJMR6h5MIICJzCCAa6gAwIBAgIUf3Sj/ANs4hR4XFlh
Tm+N8kxHqHkwCgYIKoZIzj0EAwMwNzELMAkGA1UEBhMCVVMxEzARBgNVBAoTCkV4
YW1wbGUgQ0ExEzARBgNVBAMTCmNhLmV4YW1wbGUwHhcNMjUwMTA5MTcwMzQ4WhcN
MjYwMTA5MTcwMzQ4WjA8MQswCQYDVQQGEwJVUzELMAkGA1UECBMCVkExEDAOBgNV
BAcTB0hlcm5kb24xDjAMBgNVBAMTBUFsaWNlMHYwEAYHKoZIzj0CAQYFK4EEACID
YgAEgBz7qVc3Uwgz/zZB5Y1vnkfTOv6VWBZV4XRt/iPPEJvkwKNVozR4US9yNcxX
mniTOqIlMcLRXYkCipgxf8MwUhzBnvE/25B316nopn5Fe63bXUvz5bVAjVAlIM3E
A1Gxo3YwdDAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIHgDAdBgNVHQ4EFgQUIx0A
0f7tCzkQEZgYzH3NcM2L05IwHwYDVR0jBBgwFoAUPpi8su/cNBu+cZLSo/ptvPJm
QKowFwYDVR0gBBAwDjAMBgpghkgBZQMCATAwMAoGCCqGSM49BAMDA2cAMGQCMGu/
Uypd7BaVnUjB36UtX9m5ZmPi78y51RA8WhbOv0KQVrcYtj4qOdiMVKBcoVceyAIw
RJ6U91048NAb3nicHcrGFf1UYrhbDlytK4tCa5HBxD/qAgy4/eUzA5NZwVaLK78u
MAoGCCqGSM49BAMDA2cAMGQCL2TNHPULWcCS2DqZCCiQeSwx2JPLMI14Vi977bzy
rImq5p0H3Bel6fAS8BnQ00WNAjEAhHDAlcbRuHhqdW6mOgDd5kWEGGqgixIuvEEc
fVbnNCEyEE4n0mQ99PHURnXoHwqF
"""

    def setUp(self):
        self.asn1Spec = rfc2986.CertificationRequest()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual(0, asn1Object['certificationRequestInfo']['version'])

        found = False
        for attr in asn1Object['certificationRequestInfo']['attributes']:
            if attr['type'] == rfc9883.id_statementOfPossession:
                pps, rest = der_decoder(attr['values'][0],
                    asn1Spec=rfc9883.PrivateKeyPossessionStatement())
                self.assertFalse(rest)
                self.assertTrue(asn1Object.prettyPrint())
                self.assertEqual(attr['values'][0], der_encoder(pps))

                expected = 727642999395973550353183637270955000389184235641
                self.assertEqual(expected, pps['signer']['serialNumber'])
                found = True

        self.assertTrue(found)


    def testOpenTypes(self):
        certificateAttributesMap = opentypemap.get('certificateAttributesMap')
        self.assertIn(rfc9883.id_statementOfPossession, certificateAttributesMap)

        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate,
            asn1Spec=rfc2986.CertificationRequest(), decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        found = False
        for attr in asn1Object['certificationRequestInfo']['attributes']:
            if attr['type'] == rfc9883.id_statementOfPossession:
                expected = 727642999395973550353183637270955000389184235641
                self.assertEqual(expected, attr['values'][0]['signer']['serialNumber'])
                found = True

        self.assertTrue(found)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
