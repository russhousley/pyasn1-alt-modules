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
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc9629
from pyasn1_alt_modules import rfc9690
from pyasn1_alt_modules import opentypemap


class SMIMECapRSAKEMTestCase(unittest.TestCase):
    pem_text = """\
MEcGCyqGSIb3DQEJEAMOMDgwKQYHKIGMcQICBDAeMBkGCiuBBRCGSAksAQIwCwYJ
YIZIAWUDBAIBAgEQMAsGCWCGSAFlAwQBBQ==
"""

    def setUp(self):
        self.asn1Spec = rfc5280.AlgorithmIdentifier()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))
        self.assertEqual(rfc9690.id_rsa_kem, asn1Object['algorithm'])

        algorithmIdentifierMap = opentypemap.get('algorithmIdentifierMap')
        rsa_kem_p, rest = der_decoder(asn1Object['parameters'],
            asn1Spec=algorithmIdentifierMap[rfc9690.id_rsa_kem])

        self.assertFalse(rest)
        self.assertTrue(rsa_kem_p.prettyPrint())
        self.assertEqual(asn1Object['parameters'], der_encoder(rsa_kem_p))
        self.assertEqual(rfc9690.id_kem_rsa, rsa_kem_p['kem']['algorithm'])

        kem_rsa_p, rest = der_decoder(rsa_kem_p['kem']['parameters'],
            asn1Spec=algorithmIdentifierMap[rfc9690.id_kem_rsa])

        self.assertFalse(rest)
        self.assertTrue(kem_rsa_p.prettyPrint())
        self.assertEqual(
            rsa_kem_p['kem']['parameters'], der_encoder(kem_rsa_p))
        self.assertEqual(16, kem_rsa_p['keyLength'])
        self.assertEqual(rfc9690.id_kdf_kdf3,
            kem_rsa_p['keyDerivationFunction']['algorithm'])

        kdf_p, rest = der_decoder(
            kem_rsa_p['keyDerivationFunction']['parameters'],
            asn1Spec=algorithmIdentifierMap[rfc9690.id_kdf_kdf3])

        self.assertFalse(rest)
        self.assertTrue(kdf_p.prettyPrint())
        self.assertEqual(
            kem_rsa_p['keyDerivationFunction']['parameters'],
            der_encoder(kdf_p))

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(
            substrate, asn1Spec=self.asn1Spec, decodeOpenTypes=True)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))
        self.assertEqual(rfc9690.id_rsa_kem, asn1Object['algorithm'])
        self.assertEqual(rfc9690.id_kem_rsa,
            asn1Object['parameters']['kem']['algorithm'])
        self.assertEqual(16, 
            asn1Object['parameters']['kem']['parameters']['keyLength'])


class EnveopedDataRSAKEMTestCase(unittest.TestCase):
    pem_text = """\
MIICXAYJKoZIhvcNAQcDoIICTTCCAkkCAQMxggIEpIICAAYLKoZIhvcNAQkQDQMwggHvAg
EAgBSe62fJuVp01E0vFjlmgOgBtcuknDAJBgcogYxxAgIEBIIBgMBx/Cc6+Oe9sVLga/cz
EDYQdBVKQ6vPPJPBNJnSBlNEPu2e9dPAaF5Kp2poVIFbuXaR/5+NrBXup9dPRSvzUKZGFj
1oKI6XjL96cwie5ScS+aT0ngas57vIWrFNTjNsl8VyiiZUE4x7JuiDXGsKn77SZJXE6t90
Wikzvig/aoixZpX8BmZoc8+202cY7zN2zvwQDDlB88SUlEB4MlgHpVkYa5XMq/NxTPr3n4
O9MFN/3ZrtWkzcvYvQSG+u1z6dSGswh9bIBlRrbiZxV1yYRh5EH2VUK9ld4m0PU6ZOeEjX
MdlgjQU+jTRVRmAthiNv/jcEyYrVkUTzCJ5ebVJ7VJe6EDx51i6A0CNUELBvcafZvRw4AA
+RDWMS6i8go1V1Na0Bswk/tffuUHCA0Pd9SMnDs3lva33TeGCF+4lRI/BMofHBviLHR6jf
rOMjcPsNVweD4n27fnT8qU7jlnb949ipVT2HgiRzbjfhkdq5U8fiKMB61coxIkIcFN69By
qatjAbBgorgQUQhkgJLAEBMA0GCWCGSAFlAwQCAQUAAgEQMAsGCWCGSAFlAwQBBQQYkE2+
sCcfwCCC/m01jAM1KuSua1QLeCQjMDwGCSqGSIb3DQEHATAdBglghkgBZQMEAQIEEEgMyv
66vvrO263eyviId4GAEMbKZdt73Xaw834vq2Jktm0="""

    def setUp(self):
        self.asn1Spec = rfc5652.ContentInfo()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))
        self.assertEqual(rfc5652.id_envelopedData, asn1Object['contentType'])

        ed, rest = der_decoder(asn1Object['content'],
            asn1Spec=rfc5652.EnvelopedData())
        self.assertFalse(rest)
        self.assertTrue(ed.prettyPrint())
        self.assertEqual(asn1Object['content'], der_encoder(ed))
        self.assertEqual(3, ed['version'])

        ori = ed['recipientInfos'][0]['ori']
        self.assertEqual(rfc9629.id_ori_kem, ori['oriType'])
        kemri, rest = der_decoder(ori['oriValue'],
            asn1Spec=rfc9629.KEMRecipientInfo())
        self.assertFalse(rest)
        self.assertTrue(kemri.prettyPrint())
        self.assertEqual(ori['oriValue'], der_encoder(kemri))
        self.assertEqual(0, kemri['version'])
        self.assertEqual(16, kemri['kekLength'])
        self.assertEqual(rfc9690.id_kem_rsa, kemri['kem']['algorithm'])
        self.assertEqual(rfc9690.id_aes128_wrap, kemri['wrap']['algorithm'])


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
