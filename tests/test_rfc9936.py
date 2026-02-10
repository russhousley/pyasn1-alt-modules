#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley
# Copyright (c) 2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.type import univ

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc5083
from pyasn1_alt_modules import rfc9629
from pyasn1_alt_modules import rfc9936


class AuthEnveopedDataMLKEMTestCase(unittest.TestCase):
    pem_text = """\
MIID4gYLKoZIhvcNAQkQARegggPRMIIDzQIBADGCA3ikggN0BgsqhkiG9w0BCRAN
AzCCA2MCAQCAFFmXiMN67UAO5AXRsqM2arF9gkpRMAsGCWCGSAFlAwQEAQSCAwA+
pA/GygkOLIr3bicnqzjgZS2VFZhv4YaCf+hOWW5CG4X9RZzHiZc3LJ3jHRkbOcHV
o+tt21aq3t52XMOQ/bvC+IyxdWgdQgG4HM38sk/vE68vWhq8+NivOE8CoBCm6Rnx
mHpemxwOLT8H9YqfpTnOhswUmRChaSwMpM4Ozk7u0uZpnLl2MyRS3koutcph97CB
Mww0eY73EqJOWcM86h8fnm1PvzdDo4RnQwARM29i2HB5K4Zr780dGzZb7RlSZz06
Wwwgs4a079HPY/03a9R8zEasTdjsZrBHxMlaz/HP0CikGbAC/aG2F8umHS6Rz+j/
+8uP/U1fatixWMIZ423FFAXcDAsjSXmsZY5yvd8bZ3O5ayrj5NB76GBIBAwBZ0Nv
qDnnUpsAzJq1Wi8l22PMn1V1lOaRwR5VPUo+vHYPXxnl/hRIOLTH0VkdqbXUZ0lP
2crFLMVQQGA5nb23IpjrmkwBewB4b9x9nXqletu4thw03h4oiyq3KBcdzhQ80WlT
+YTBrtVZ5WuqDOZY0yzOQvRAdQTNelea0O+bdxNeqjm2+To6LlmXgH8GNhyD9OZ/
jj+c9oMWARUU9dhaGBzq1xTNSUDk66wB1mUo2jL4nOoEKOjrytz4qhiMn2LoWxlX
ZVt/4rjXlzt6cia2bZO/eyMvPc9lPIS07PGpkg2xlJrXULVGpVUqIOVJCXGbjAwH
BW/LfldK0qMuyVAB3ehEgb530DntW/dCYuzzmB8bANM2apwuBhxH4kGgYcYklWDS
uERqSAw4woupidn2itxLuvKiC0fkkjEoxyNC1Zf9olneC4PCBW1rd+eZsxkySqUL
HWWcKlYCm3RTxfO6UkPZ+nSdkXxA2dEB5FO8ixDkKnwIkyPAJveD4QC5+m5wFEJN
pvo3kryVfughnQFrdz8o/tzJYqSFq6/+wCMoGXHimqaJg57P0mGekih80jDbJqJQ
fMUA6xx6UpO1/pF64pvxrTUBJPijEWNSFLQR259n07hb1xUBhTfqRbQfQbTGYFEw
DQYLKoZIhvcNAQkQAxwCARAwCwYJYIZIAWUDBAEFBBjAUOQ5L5wU3QrCIgID8xfX
AflPndknePUwOgYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBBjARBAxcpXRouBvwO42n
GGwCARCADZTIaJqZ0sOOGS+muggEEFzxeGxXx0ArVPyTwwpKRTM=
"""

    def setUp(self):
        self.asn1Spec = rfc5652.ContentInfo()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))
        self.assertEqual(rfc5083.id_ct_authEnvelopedData,
            asn1Object['contentType'])

        aed, rest = der_decoder(asn1Object['content'],
            asn1Spec=rfc5083.AuthEnvelopedData())
        self.assertFalse(rest)
        self.assertTrue(aed.prettyPrint())
        self.assertEqual(asn1Object['content'], der_encoder(aed))
        self.assertEqual(0, aed['version'])

        ori = aed['recipientInfos'][0]['ori']
        self.assertEqual(rfc9629.id_ori_kem, ori['oriType'])
        kemri, rest = der_decoder(ori['oriValue'],
            asn1Spec=rfc9629.KEMRecipientInfo())
        self.assertFalse(rest)
        self.assertTrue(kemri.prettyPrint())
        self.assertEqual(ori['oriValue'], der_encoder(kemri))
        self.assertEqual(0, kemri['version'])
        self.assertEqual(univ.OctetString(
            hexValue='599788c37aed400ee405d1b2a3366ab17d824a51'),
            kemri['rid']['subjectKeyIdentifier'])
        self.assertEqual(rfc9936.id_alg_ml_kem_512,
            kemri['kem']['algorithm'])
        self.assertEqual(rfc9936.id_alg_hkdf_with_sha256,
            kemri['kdf']['algorithm'])


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
