#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley
# Copyright (c) 2023-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc9629

from pyasn1_alt_modules import opentypemap


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


class ORIKEMRecipientInfoTestCase(unittest.TestCase):

    def testORIOpenTypeMap(self):
        otherRecipientInfoMap = opentypemap.get('otherRecipientInfoMap')
        self.assertIn(rfc9629.id_ori_kem, otherRecipientInfoMap)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
