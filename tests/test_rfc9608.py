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

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc9608


class NoRevAvailCertificateTestCase(unittest.TestCase):
    cert_pem_text = """\
MIICizCCAhGgAwIBAgIJAKWzVCgbsG5RMAoGCCqGSM49BAMDMD8xCzAJBgNVBAYT
AlVTMQswCQYDVQQIDAJWQTEQMA4GA1UEBwwHSGVybmRvbjERMA8GA1UECgwIQm9n
dXMgQ0EwHhcNMjMwNTE5MTc1NzMwWhcNMjMwNTI2MTc1NzMwWjA/MRgwFgYDVQQD
Ew93d3cuZXhhbXBsZS5jb20xFjAUBgNVBAoTDUV4YW1wbGUgQ29ycC4xCzAJBgNV
BAYTAlVTMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEVyVaFAmNjlVGE8vcwnSqa6t6
4CLfG4iaYazd9dZrUPyD1/7P9CcR+881jkrRMMrgKiZh0v/xkdwdt4NhI4L6I4vE
WqDmO0IAc+FT5yyurBWMkIUildRvDrPoCogafOJso4HYMIHVMAkGA1UdOAQCBQAw
IgYDVR0RBBswGYYXaHR0cDovL3d3dy5leGFtcGxlLmNvbS8wCwYDVR0PBAQDAgeA
MBMGA1UdJQQMMAoGCCsGAQUFBwMBMEIGCWCGSAGG+EIBDQQ1FjNUaGlzIGNlcnRp
ZmljYXRlIGNhbm5vdCBiZSB0cnVzdGVkIGZvciBhbnkgcHVycG9zZS4wHQYDVR0O
BBYEFIQ6BKw0c2EZOZq2RWrTfGjTXz3cMB8GA1UdIwQYMBaAFPI12zQE2qVV8r1p
A5mwYuziFQjBMAoGCCqGSM49BAMDA2gAMGUCMQDSz7l1NptMer/vrjpvhpGXNBNH
5C99shVOvKYlkfn7BCvYmvGG6VaR7xiT4uhbd1ECMERXfNTrV0TDuB4RHYfsJ2sL
hsc0TPUNfghSWecand/COC4SDVid/Xyg7A1DQrzTvg==
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Certificate()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.cert_pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        found = False
        for extn in asn1Object['tbsCertificate']['extensions']:
            if extn['extnID'] in rfc5280.certificateExtensionsMap:
                extnValue, rest = der_decoder(
                    extn['extnValue'],
                    asn1Spec=rfc5280.certificateExtensionsMap[extn['extnID']])
                self.assertFalse(rest)
                self.assertEqual(extn['extnValue'], der_encoder(extnValue))

                if extn['extnID'] == rfc9608.id_ce_noRevAvail:
                    found = True

        self.assertTrue(found)

suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
