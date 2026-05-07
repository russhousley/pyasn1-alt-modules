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
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc9977
from pyasn1_alt_modules import opentypemap


class RPKIPrefixListTestCase(unittest.TestCase):
    pem_text = """\
MIIGQAYJKoZIhvcNAQcCoIIGMTCCBi0CAQMxDTALBglghkgBZQMEAgEwDQYLKoZ
IhvcNAQkQATmgggRaMIIEVjCCAz6gAwIBAgIUJ605QIPX8rW5m4Zwx3WyuW7hZv
swDQYJKoZIhvcNAQELBQAwMzExMC8GA1UEAxMoM0FDRTJDRUY0RkIyMUI3RDExR
TNFMTg0RUZDMUUyOTdCMzc3ODY0MjAeFw0yNjA1MDcyMTIyNDlaFw0yNzAzMDMy
MTIyNDlaMDMxMTAvBgNVBAMTKDkxNDY1MkEzQkQ1MUMxNDQyNjAxOTg4ODlGNUM
0NUFCRjA1M0ExODcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCycT
QrOb/qB2W3i3Ki8PhA/DEWyii2TgGo9pgCwO9lsIRI6Zb/k+aSiWWP9kSczlcQg
tPCVwr62hTQZCIowBN0BL0cK0/5k1imJdi5qdM3nvKswM8CnoR11vB8pQFwruZm
r5xphXRvE+mzuJVLgu2V1upmBXuWloeymudh6WWJ+GDjwPXO3RiXBejBrOFNXha
FLe08y4DPfr/S/tXJOBm7QzQptmbPLYtGfprYu45liFFqqP94UeLpISfXd36AKG
zqTFCcc3EW9l5UFE1MFLlnoEogqtoLoKABt0IkOFGKeC/EgeaBdWLe469ddC9rQ
ft5w6g6cmxG+aYDdIEB34zrAgMBAAGjggFgMIIBXDAdBgNVHQ4EFgQUkUZSo71R
wUQmAZiIn1xFq/BToYcwHwYDVR0jBBgwFoAUOs4s70+yG30R4+GE78Hil7N3hkI
wDgYDVR0PAQH/BAQDAgeAMBgGA1UdIAEB/wQOMAwwCgYIKwYBBQUHDgIwYQYDVR
0fBFowWDBWoFSgUoZQcnN5bmM6Ly9ycGtpLmV4YW1wbGUubmV0L3JlcG9zaXRvc
nkvM0FDRTJDRUY0RkIyMUI3RDExRTNFMTg0RUZDMUUyOTdCMzc3ODY0Mi5jcmww
bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlByc3luYzovL3Jwa2kuZXhhbXB
sZS5uZXQvcmVwb3NpdG9yeS8zQUNFMkNFRjRGQjIxQjdEMTFFM0UxODRFRkMxRT
I5N0IzNzc4NjQyLmNlcjAfBggrBgEFBQcBBwEB/wQQMA4wDAQCAAEwBgMEAMAAA
jANBgkqhkiG9w0BAQsFAAOCAQEAUIykBaqYnR/U+AXYzCqRbMqdygFY9R11fiNQ
ubpkf5kEYHFxTut0CZLz9dToxuHRDLbPhjJvCi3cDkb2ICy1Fdcit5oi9jFl1MD
/sFa4l/FWGM07PhgKY+Isz3DXEw9furF7Al3IgbB0and5HQrvQbO6AnqixSYDff
ANsnZssojMzlHJIA9OLHIuhGZ66t+yh2VclhwV7JdS+0EdyA0npIrTGyp//pD5v
rigF04y+J4Y61jFXfmbWZbNJF/bMzFeBxD2PKaEuwixf65s3yI0JDjBbXjUtUhq
yty0IZqV2HcuWU7MKH9Qc/wvrJDd4K4xTbkWWYgAql7bgmJTHpW2GzGCAaowggG
mAgEDgBSRRlKjvVHBRCYBmIifXEWr8FOhhzALBglghkgBZQMEAgGgazAaBgkqhk
iG9w0BCQMxDQYLKoZIhvcNAQkQATkwHAYJKoZIhvcNAQkFMQ8XDTI2MDUwNzIxM
jI0OVowLwYJKoZIhvcNAQkEMSIEIGMBdMKw5mjZYL9qP4ivwgMt8g2+qEO0+Dcn
N5vQO1bNMA0GCSqGSIb3DQEBAQUABIIBAKzRicWBpSyN5nw39eDNfVai2H1mO0n
APgZUmVF/vgSCWtR0da1iZots4qwn0XwvvIgu5eZ7edhn9axLXhjTAOQajT4cOw
9+raD7+SYdBIAUgZpuFy3Olnu4HykCd8Ub44lPfZVG1lF1LeN248+rWgozpE7xz
Dv5G83OslbvVzGXaVShJM4fsDfpkpKoQ4LszlBeqguU2yTm3XWVjkxH7VJvTtIT
SzO3jAqwqnCjfu3mnxCoz7LKES4DPZERsFoJv1zyDdHIXjPnfZuTBjjCOubjaQx
rRwgZtQ8Ljz3gpz1VzL9mKAv0pUzcyxtQfakHwdYtxyO33z2InljtTFJCroI=
"""

    def testDerCodec(self):
        cmsContentTypesMap = opentypemap.get('cmsContentTypesMap')
        self.assertIn(rfc9977.id_ct_prefixlenCSVwithCRLF, cmsContentTypesMap)

        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate,
            asn1Spec=rfc5652.ContentInfo())
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual(rfc5652.id_signedData, asn1Object['contentType'])
        sd, rest = der_decoder(asn1Object['content'],
            asn1Spec=rfc5652.SignedData())
        self.assertFalse(rest)
        self.assertTrue(sd.prettyPrint())
        self.assertEqual(asn1Object['content'], der_encoder(sd))

        self.assertEqual(3, sd['version'])
        self.assertEqual(rfc9977.id_ct_prefixlenCSVwithCRLF,
            sd['encapContentInfo']['eContentType'])
        # it is a detached signature
        self.assertFalse(sd['encapContentInfo']['eContent'].hasValue())

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate,
            asn1Spec=rfc5652.ContentInfo(), decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        sd = asn1Object['content']
        self.assertEqual(3, sd['version'])
        self.assertEqual(rfc9977.id_ct_prefixlenCSVwithCRLF,
            sd['encapContentInfo']['eContentType'])
        # it is a detached signature
        self.assertFalse(sd['encapContentInfo']['eContent'].hasValue())


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
