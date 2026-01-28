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
from pyasn1_alt_modules import rfc9509


class NFVEKUTestCase(unittest.TestCase):
    cert_pem_text = """\
MIIDWzCCAuKgAwIBAgIJAKWzVCgbsG5TMAoGCCqGSM49BAMDMD8xCzAJBgNVBAYT
AlVTMQswCQYDVQQIDAJWQTEQMA4GA1UEBwwHSGVybmRvbjERMA8GA1UECgwIQm9n
dXMgQ0EwHhcNMjMwOTI2MTcwNDE0WhcNMjQwOTI1MTcwNDE0WjBaMQswCQYDVQQG
EwJVUzEqMCgGA1UECgwhNWdjLm1uYzAxMi5tY2MzNDUuM2dwcG5ldHdvcmsub3Jn
MR8wHQYDVQQDDBZhbWYxLmNsdXN0ZXIxLm5ldDIuYW1mMHYwEAYHKoZIzj0CAQYF
K4EEACIDYgAE7RSQ7GmVAzQsfifYsF9C45i1f86fgmfFl6ELlUgYjt5fG2ZWwIE3
oF/SQAmAD5cvusDYqIpx4iGOSCJnvgId1iMvphRTqw4gFK6Q49Zk/thG2BMdImny
4XjrwnRWzfGwo4IBjTCCAYkwgbcGA1UdEQSBrzCBrII4YW1mMS5jbHVzdGVyMS5u
ZXQyLmFtZi41Z2MubW5jMDEyLm1jYzM0NS4zZ3BwbmV0d29yay5vcmeCQWFtZjEu
Y2FsbGJhY2suY2x1c3RlcjEubmV0Mi5hbWYuNWdjLm1uYzAxMi5tY2MzNDUuM2dw
cG5ldHdvcmsub3Jnhi11cm46dXVpZDpmODFkNGZhZS03ZGVjLTExZDAtYTc2NS0w
MGEwYzkxZTZiZjYwCwYDVR0PBAQDAgeAMCcGA1UdJQQgMB4GCCsGAQUFBwMBBggr
BgEFBQcDAgYIKwYBBQUHAycwHQYDVR0OBBYEFCIMH3AXpn6uXdyu6WrlwdCAbwyy
MB8GA1UdIwQYMBaAFPI12zQE2qVV8r1pA5mwYuziFQjBMBMGCCsGAQUFBwEiBAcw
BRYDQU1GMEIGCWCGSAGG+EIBDQQ1FjNUaGlzIGNlcnRpZmljYXRlIGNhbm5vdCBi
ZSB0cnVzdGVkIGZvciBhbnkgcHVycG9zZS4wCgYIKoZIzj0EAwMDZwAwZAIwHYnv
q2hGDO6v+keLrOU76L5NacqSW8cqtumzjMKZrUZWDyyCWw1w3a2Bb/2A3StDAjAK
bcZvtuatkNjj3fCInbwVPeWHzAGgf/P4yAoKCsQHjOo+moTnE7hUKYp3Zw6KvPs=
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
                self.assertTrue(extnValue.prettyPrint())
                self.assertEqual(extn['extnValue'], der_encoder(extnValue))

                if extn['extnID'] == rfc5280.id_ce_extKeyUsage:
                    self.assertIn(rfc9509.id_kp_oauthAccessTokenSigning, extnValue)
                    found = True

        self.assertTrue(found)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
