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
from pyasn1_alt_modules import rfc9809


class UpdatePackageSignCertTestCase(unittest.TestCase):
    pem_text = """\
MIIDCjCCAmygAwIBAgIUKuHXi4pIOKhoeE9lpzwTxbttc1kwCgYIKoZIzj0EAwQw
ejEzMDEGA1UEAwwqTWFudWZhY3R1cmVyIFNpZ25lciBJc3N1aW5nIFRFU1QgQ0Eg
djAuMC4xMR4wHAYDVQQLDBVDeWJlciBTZWN1cml0eSBEb21haW4xFjAUBgNVBAoM
DVN5c3RlbSBQaWxsYXIxCzAJBgNVBAYTAkVVMB4XDTI1MDYzMDA5MTgyOFoXDTI3
MDYzMDA5MTgyOFowZzEgMB4GA1UEAwwXVEVTVCBVcGRhdGUgU2lnbmVyIHYwLjEx
HjAcBgNVBAsMFUN5YmVyIFNlY3VyaXR5IERvbWFpbjEWMBQGA1UECgwNU3lzdGVt
IFBpbGxhcjELMAkGA1UEBhMCRVUwgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABAFJ
WkEgy3P2PE0zyKdKjMHCFiNqROH2W7rl130fsebBzag1tvwACOKz8CH1y3qTt6/O
3lXun3c5I44jRCxLBAypKACVreaBqeW2CrypVXopdFL2nySRRycFyptHxs6EpDLA
B2w3hxQR77bgZkflGJCdmV2zKnWl1vMCs31Hf8PtsaaYnKOBnzCBnDAdBgNVHQ4E
FgQUAGr50rp69OdC47Idq+0D13JHljQwHwYDVR0jBBgwFoAUkstsfWlvbDP/0Opi
rt1T/oA8ZXQwDgYDVR0PAQH/BAQDAgeAMCIGA1UdJQEB/wQYMBYGCisGAQQBoWks
AQMGCCsGAQUFBwMrMAwGA1UdEwEB/wQCMAAwGAYDVR0gBBEwDzANBgsrBgEEAaFp
JgQCATAKBggqhkjOPQQDBAOBiwAwgYcCQTT6RDddEveakzsaDavdacUKLIQ+LmZp
ybVQm2/OgFzjny6ll62YQmI7DVpL9wjStvriaxoNGf74bGxV2UPLod2MAkIBj474
Y4yEw6QSLZUugTpFrnubBmQowIY4aaS5Xt80uZQb8jZrl+xhJB1iqng1xMDqZhRP
904PwKrA5TAOopLtxCY=
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Certificate()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        found = False
        for extn in asn1Object['tbsCertificate']['extensions']:
            if extn['extnID'] == rfc5280.id_ce_extKeyUsage:
                extnValue, rest = der_decoder(
                    extn['extnValue'], asn1Spec=rfc5280.ExtKeyUsageSyntax())
                self.assertFalse(rest)
                self.assertTrue(extnValue.prettyPrint())
                self.assertEqual(extn['extnValue'], der_encoder(extnValue))

                for eku in extnValue:
                    if eku == rfc9809.id_kp_updatePackageSigning:
                        found = True

        self.assertTrue(found)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
