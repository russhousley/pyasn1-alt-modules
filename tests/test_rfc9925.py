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

from pyasn1.type import char

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc9925


class UnsignedCertificateTestCase(unittest.TestCase):
    pem_text = """\
MIIBEDCB/qADAgECAgEBMAoGCCsGAQUFBwYkMBAxDjAMBggrBgEFBQcZAQwAMB4X
DTI1MDYwMzE5MDc1NloXDTI2MDYwMzE5MDc1NlowADBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABB5ZQOWidrYaG0fqOmjtiBe7U0fYw1d7gfqoX0GxlkFnGsL0jgX7
UD7fBEts73hMpRmadwkwShwr4FN+ssfEYRmjWTBXMA4GA1UdDwEB/wQEAwIHgDAT
BgNVHSUEDDAKBggrBgEFBQcDATAwBgNVHREEKTAnggtleGFtcGxlLmNvbYILZXhh
bXBsZS5uZXSCC2V4YW1wbGUub3JnMAoGCCsGAQUFBwYkAwEA
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Certificate()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        algids = (asn1Object['signatureAlgorithm'],
                  asn1Object['tbsCertificate']['signature'])

        for algid in algids:
            self.assertEqual(algid['algorithm'], rfc9925.id_alg_unsigned)
            self.assertFalse(algid['parameters'].hasValue())

        found = False
        for rdn in asn1Object['tbsCertificate']['issuer']['rdnSequence']:
            for attr in rdn:
                if attr['type'] == rfc9925.id_rdna_unsigned:
                    av, rest = der_decoder(attr['value'],
                        asn1Spec=char.UTF8String())
                    self.assertEqual(u'', av)
                    found = True

        self.assertTrue(found)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
