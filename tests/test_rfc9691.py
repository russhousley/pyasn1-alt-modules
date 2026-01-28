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
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc9691


class RPKISignedTALTestCase(unittest.TestCase):
    pem_text = """\
MIIKfwYJKoZIhvcNAQcCoIIKcDCCCmwCAQMxDTALBglghkgBZQMEAgEwggSJBgsq
hkiG9w0BCRABMqCCBHgEggR0MIIEcDCCAXQwDAwKTXkgbmljZSBUQTA+FhpodHRw
czovL2V4YW1wbGUuY29tL3RhLmNlchYgcnN5bmM6Ly9leGFtcGxlLmNvbS9yc3lu
Yy90YS5jZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCxQQ12NJzG
ISfJdy58LvFEtIzepr8ayyAoSEkbXsvF6NwMRdzybrkBc7emFomJtH3hTuKqQJno
rda1ffUI1ix4gCNvTJwuCjofkXTjbDqgjV5yLb4m34z0Mw5ZWwXqQ47MgThvUT97
m/prF4eVtTBPjM9MFBnhWjDYxwjauNIWj9tjqtUJWEP86r4o3nHbACGQnWT1zbO8
7cZWmmRxQJmgxdzxr5BEst5X1KIKbITxySVVpPUsIVALTObzJr3jQGL7BlzIR6vK
q0Chu+odFoctwz+kRguKTF3mlRv3zlYTrcBm9yV7PEwHBmXtN1l67yAAoZkpB0Q1
48I/LFPGnqsrAgMBAAGgggF4MIIBdDAMDApNeSBuaWNlIFRBMD4WGmh0dHBzOi8v
ZXhhbXBsZS5jb20vdGEuY2VyFiByc3luYzovL2V4YW1wbGUuY29tL3JzeW5jL3Rh
LmNlcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALFBDXY0nMYhJ8l3
Lnwu8US0jN6mvxrLIChISRtey8Xo3AxF3PJuuQFzt6YWiYm0feFO4qpAmeit1rV9
9QjWLHiAI29MnC4KOh+RdONsOqCNXnItvibfjPQzDllbBepDjsyBOG9RP3ub+msX
h5W1ME+Mz0wUGeFaMNjHCNq40haP22Oq1QlYQ/zqvijecdsAIZCdZPXNs7ztxlaa
ZHFAmaDF3PGvkESy3lfUogpshPHJJVWk9SwhUAtM5vMmveNAYvsGXMhHq8qrQKG7
6h0Why3DP6RGC4pMXeaVG/fOVhOtwGb3JXs8TAcGZe03WXrvIAChmSkHRDXjwj8s
U8aeqysCAwEAAaGCAXgwggF0MAwMCk15IG5pY2UgVEEwPhYaaHR0cHM6Ly9leGFt
cGxlLmNvbS90YS5jZXIWIHJzeW5jOi8vZXhhbXBsZS5jb20vcnN5bmMvdGEuY2Vy
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsUENdjScxiEnyXcufC7x
RLSM3qa/GssgKEhJG17LxejcDEXc8m65AXO3phaJibR94U7iqkCZ6K3WtX31CNYs
eIAjb0ycLgo6H5F042w6oI1eci2+Jt+M9DMOWVsF6kOOzIE4b1E/e5v6axeHlbUw
T4zPTBQZ4Vow2McI2rjSFo/bY6rVCVhD/Oq+KN5x2wAhkJ1k9c2zvO3GVppkcUCZ
oMXc8a+QRLLeV9SiCmyE8cklVaT1LCFQC0zm8ya940Bi+wZcyEeryqtAobvqHRaH
LcM/pEYLikxd5pUb985WE63AZvclezxMBwZl7TdZeu8gAKGZKQdENePCPyxTxp6r
KwIDAQABoIIEOTCCBDUwggMdoAMCAQICAQEwDQYJKoZIhvcNAQELBQAwMzExMC8G
A1UEAxMoMEVGOEU5MjZDQkE4RDYwNDEyMkUwQjlDNjMzRUJCNTE3QkE0RkYyMTAe
Fw0yMjEwMTMxMTM3NTdaFw0yMjEwMTQxMTM3NTdaMDMxMTAvBgNVBAMTKDQ4MDQy
OEI3N0EwNzVERTMwMDRFRjBFNTdDNzg1RUFBN0E3NkQ0OEQwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCpoUuZBf5mI+ZkI6KFJlX6Rt0u2GBp+WMNaY0W
cDBKm4ngiAVZdNXR5yYse9wqXdBqBVe3l7cy4MNx91bXCng7afsA18S6ar5vFlVe
42bq0LCVxdBgZrvdxgtyiQntx1IlUNZnxr8y2ZJe8K9/FwU+9zG1fn3DjrITPy6y
+o/ejQ2RI/+V9G5fbxHAccTk9+xxuwaM14j84adWajSaHmjlQPSrpOdmxIAyjQae
txmyW0HjYqm2lSeqCVE0CMQVxf59VGYq9uQWZn9yQdgJHJ5mXtoVTGIyQ5b/nvHr
IDS3raebRJQprs8b580YOdX4WqLCP4NTepYjZf/w/O1Czr6NAgMBAAGjggFSMIIB
TjAdBgNVHQ4EFgQUSAQot3oHXeMATvDlfHheqnp21I0wHwYDVR0jBBgwFoAUDvjp
Jsuo1gQSLgucYz67UXuk/yEwDgYDVR0PAQH/BAQDAgeAMC4GA1UdHwQnMCUwI6Ah
oB+GHXJzeW5jOi8vZXhhbXBsZS5jb20vdGEvdGEuY3JsMDwGCCsGAQUFBwEBBDAw
LjAsBggrBgEFBQcwAoYgcnN5bmM6Ly9leGFtcGxlLmNvbS9yc3luYy90YS5jZXIw
OgYIKwYBBQUHAQsELjAsMCoGCCsGAQUFBzALhh5yc3luYzovL2V4YW1wbGUuY29t
L3RhL3Rhay50YWswGAYDVR0gAQH/BA4wDDAKBggrBgEFBQcOAjAhBggrBgEFBQcB
BwEB/wQSMBAwBgQCAAEFADAGBAIAAgUAMBUGCCsGAQUFBwEIAQH/BAYwBKACBQAw
DQYJKoZIhvcNAQELBQADggEBAJroqz79+WXhM24E4szybvKtnT5wEJlnnsC8X9bQ
jGUSUdUoZzpqx85IrONhBTXvoXXY5iEeYj/F3xcKZffKIssxBpgG2s34SonwV/M0
NEm4vQx/xMBreU7Hkay41RHSKu8nJLBijZc4cR0y7ojwIPy2ZV1gaY8RzJGJtARv
gecYBG5ULsiEp9tE0ayYgG/vJ/+NclfHHsh6cmqSuGqFYFQI+zdlcKiA/ks900Uz
DldRoQSHdkzlndePrs0it2LLUdVoNQ9dK2rmBfyRjmErsHBbd6GiGCq3NkpTWu2H
45Sm5TVI+xCMCw7/V6NdI6J9nsGF5qeeEVhNLm7iiixeW+kxggGMMIIBiAIBA4AU
SAQot3oHXeMATvDlfHheqnp21I0wCwYJYIZIAWUDBAIBoE0wGgYJKoZIhvcNAQkD
MQ0GCyqGSIb3DQEJEAEyMC8GCSqGSIb3DQEJBDEiBCCFIgXoWqrrgxVPyEacaAzG
Tw/hUHU1MU3CG3uQpXbPgTANBgkqhkiG9w0BAQEFAASCAQCkmO0wJ8i9bX/gCuUH
ihv+iHfx54eWMo0UQHuc8HlFBCUOfsySzvrpDtV/Au806xtOIyMR5tMROVgHiDvQ
xITEnxkdwum2nnryCIcDkr3IaDd4+oEAENHhrtvAMH6yLNSljGc0UZT62EwB7vSo
FQmIGBUqFGWfaCzoYjV/ZU8l7NU2lNVY7OK5vPzXPIi80lE60J+s7eje0LjyPclk
GOXJsEVnh+vMJLuL8gHM061yrffEV+fQsjqaRtnFsYDz4tSoTFTtedo5Mm+I167Q
47JAinnmLDcJZ94nJ29Isq3rleD0/15jEsnMEcfPXsWMABrPSxhDBoQuwzNQgZaD
Eo9c
"""

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        
        layers = { }
        layers.update(rfc5652.cmsContentTypesMap)
        self.assertIn(rfc9691.id_ct_signedTAL, layers)

        getNextLayer = {
            rfc5652.id_ct_contentInfo: lambda x: x['contentType'],
            rfc5652.id_signedData: lambda x: x['encapContentInfo']['eContentType'],
        }

        getNextSubstrate = {
            rfc5652.id_ct_contentInfo: lambda x: x['content'],
            rfc5652.id_signedData: lambda x: x['encapContentInfo']['eContent'],
        }

        layer = rfc5652.id_ct_contentInfo
        while layer in getNextLayer:
            asn1Object, rest = der_decoder(substrate, asn1Spec=layers[layer])
            self.assertFalse(rest)
            self.assertTrue(asn1Object.prettyPrint())
            self.assertEqual(substrate, der_encoder(asn1Object))

            substrate = getNextSubstrate[layer](asn1Object)
            layer = getNextLayer[layer](asn1Object)

        self.assertEqual(rfc9691.id_ct_signedTAL, layer)

        asn1Object, rest = der_decoder(substrate,
            asn1Spec=rfc9691.TAK())
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual(0, asn1Object['version'])
        self.assertIn(u'nice', asn1Object['current']['comments'][0])

        count = 0
        for url in asn1Object['current']['certificateURIs']:
            self.assertIn('example.com', url)
            count += 1
        for url in asn1Object['predecessor']['certificateURIs']:
            self.assertIn('example.com', url)
            count += 1
        for url in asn1Object['successor']['certificateURIs']:
            self.assertIn('example.com', url)
            count += 1
        self.assertEqual(6, count)

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.pem_text)

        asn1Object, rest = der_decoder(substrate,
            asn1Spec=rfc5652.ContentInfo(), decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        substrate = asn1Object['content']['encapContentInfo']['eContent']
        asn1Object, rest = der_decoder(substrate,
            asn1Spec=rfc9691.TAK(), decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual(0, asn1Object['version'])
        self.assertIn(u'nice', asn1Object['current']['comments'][0])

        count = 0
        for url in asn1Object['current']['certificateURIs']:
            self.assertIn('example.com', url)
            count += 1
        for url in asn1Object['predecessor']['certificateURIs']:
            self.assertIn('example.com', url)
            count += 1
        for url in asn1Object['successor']['certificateURIs']:
            self.assertIn('example.com', url)
            count += 1
        self.assertEqual(6, count)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
