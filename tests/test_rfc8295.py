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
from pyasn1_alt_modules import rfc2985
from pyasn1_alt_modules import rfc4211
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc6402
from pyasn1_alt_modules import rfc8295


class PKCS10CertificationRequestTestCase(unittest.TestCase):
    pem_text = """\
MIIBnQYKKoZIhvcNAQkZBTGCAY0wggGJBggrBgEFBQcMAqCCAXswggF3MIIBc6CC
AW8CAQAwggFoMIHvAgEAMHAxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJWQTEQMA4G
A1UEBxMHSGVybmRvbjEQMA4GA1UEChMHRXhhbXBsZTEOMAwGA1UEAxMFQWxpY2Ux
IDAeBgkqhkiG9w0BCQEWEWFsaWNlQGV4YW1wbGUuY29tMHYwEAYHKoZIzj0CAQYF
K4EEACIDYgAE+M2fBy/sRA6V1pKFqecRTE8+LuAHtZxes1wmJZrBBg+bz7uYZfYQ
xI3dVB0YCSD6Mt3yXFlnmfBRwoqyArbjIBYrDbHBv2k8Csg2DhQ7qs/wto8hMKoF
gkcscqIbiV7ZoAAwCgYIKoZIzj0EAwMDaAAwZQIxAIpD3F8fpO4tq0YXdLAvlOJ0
b6Fm5mjaqLrJDEzBS4WUfJasvlHtuaMYyygfNHC/QQIwAPKspeIrY330CGyNnFwT
9oecmSfdf+ZTX+UKe6IIvtTNbiDFSWkUPvrBwvzfMioc
"""

    def setUp(self):
        self.asn1Spec = rfc5652.Attribute()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual(1, len(asn1Object['attrValues']))
        self.assertEqual(rfc2985.pkcs_9_at_pkcs7PDU, asn1Object['attrType'])

        asn1Spec = rfc5652.ContentInfo()
        ci, rest = der_decoder(asn1Object['attrValues'][0], asn1Spec=asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(ci.prettyPrint())
        self.assertEqual(asn1Object['attrValues'][0], der_encoder(ci))

        self.assertEqual(rfc6402.id_cct_PKIData, ci['contentType'])

        asn1Spec = rfc8295.PKIData()
        pkidata, rest = der_decoder(ci['content'], asn1Spec=asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(pkidata.prettyPrint())
        self.assertEqual(ci['content'], der_encoder(pkidata))

        self.assertEqual(1, len(pkidata['reqSequence']))
        self.assertTrue(pkidata['reqSequence'][0]['tcr'].hasValue())
        self.assertEqual(0,  pkidata['reqSequence'][0]['tcr']['bodyPartID'])


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
