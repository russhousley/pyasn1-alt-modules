#
# This file is part of pyasn1-alt-modules software.
#
# Copyright (c) 2024-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc9582
from pyasn1_alt_modules import opentypemap


class RPKIROATestCase(unittest.TestCase):
    roa_pem_text = """\
MIIHCwYJKoZIhvcNAQcCoIIG/DCCBvgCAQMxDTALBglghkgBZQMEAgEwNwYLKoZIhvcNAQkQ
ARigKAQmMCQCAjzKMB4wHAQCAAIwFjAJAwcAIAEGfCCMMAkDBwAqDrJAAACgggT7MIIE9zCC
A9+gAwIBAgIDAIb5MA0GCSqGSIb3DQEBCwUAMDMxMTAvBgNVBAMTKDM4ZTE0ZjkyZmRjN2Nj
ZmJmYzE4MjM2MTUyM2FlMjdkNjk3ZTk1MmYwHhcNMjIwNjE3MDAyNDIyWhcNMjMwNzAxMDAw
MDAwWjAzMTEwLwYDVQQDEyhBM0Q5NjQyNDU3NDlCQjZERDVBQjFGMkU4MzBFMzNBNkM1MTQ2
RThGMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4CRG1t04YFLq3fctx2ThNfr6
Vxsd2wZzcZhQJgUdlvUyfUPISWMwuPfpGjviqtCEzh5aNePGpLopkIES08egzTmJ78Is6+kW
LXwy9CcwT7gmP9qOTSEi8h4qcyajxHbAwDEjROVNSujhLGeB74S9IQTn2Ertp2Et2xPq/kXw
+eiBHtOL2h2I7/UOZxHOHuNuHby+VbhFaxgPA7rVfdlUAf9yYxQvyZtB7kHT/EwAR4c9SYWu
0rvbWNJwWehzlT74V1XaknRXQjkKYHe34Fyyx9FY86uX4uN8rPuIzkd7n6g81pUZRIuk/3tc
/DjbHNAD3qWVQ+0aqNdkunoJhQccZwIDAQABo4ICEjCCAg4wHQYDVR0OBBYEFKPZZCRXSbtt
1asfLoMOM6bFFG6PMB8GA1UdIwQYMBaAFDjhT5L9x8z7/BgjYVI64n1pfpUvMBgGA1UdIAEB
/wQOMAwwCgYIKwYBBQUHDgIwZAYDVR0fBF0wWzBZoFegVYZTcnN5bmM6Ly9jaGxvZS5zb2Jv
cm5vc3QubmV0L3Jwa2kvUklQRS1ubGpvYnNuaWpkZXJzL09PRlBrdjNIelB2OEdDTmhVanJp
ZldsLWxTOC5jcmwwZAYIKwYBBQUHAQEEWDBWMFQGCCsGAQUFBzAChkhyc3luYzovL3Jwa2ku
cmlwZS5uZXQvcmVwb3NpdG9yeS9ERUZBVUxUL09PRlBrdjNIelB2OEdDTmhVanJpZldsLWxT
OC5jZXIwDgYDVR0PAQH/BAQDAgeAMIGoBggrBgEFBQcBCwSBmzCBmDBfBggrBgEFBQcwC4ZT
cnN5bmM6Ly9jaGxvZS5zb2Jvcm5vc3QubmV0L3Jwa2kvUklQRS1ubGpvYnNuaWpkZXJzL285
bGtKRmRKdTIzVnF4OHVndzR6cHNVVWJvOC5yb2EwNQYIKwYBBQUHMA2GKWh0dHBzOi8vY2hs
b2Uuc29ib3Jub3N0Lm5ldC9ycGtpL25ld3MueG1sMCsGCCsGAQUFBwEHAQH/BBwwGjAYBAIA
AjASAwcAIAEGfCCMAwcAKg6yQAAAMA0GCSqGSIb3DQEBCwUAA4IBAQAY4bd+Y1Os1MbxGWLU
d7rNVG0c3e0FOwtUOE/Qprt5gkCHO2L19/R1jnXlAaJPID5VhUNl2y/AiwmP47vhk+fvtEdB
wniszL8wCk5b6wwufn1z5/stQ85GRmsqJw5nkOYCyWpTP8k+TUa4w32xNj1dX78FwadDVeSP
yMgJ0860mkXbV1/82/D60zrWQsVAZiYebhni1QAqmpsxZwdZceFRRVY48YDPOZ73ZBZvf0g6
Boy1+djlcAkugA92OKLzqjHWfY2iWZkcxXmFDthoeVCGQePkHMOigOyjZPcM8EXumo1rwI7N
4CPs0VkmCVCZABYVQ0HJvU08i/Wf6X1VRbNcMYIBqjCCAaYCAQOAFKPZZCRXSbtt1asfLoMO
M6bFFG6PMAsGCWCGSAFlAwQCAaBrMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABGDAcBgkq
hkiG9w0BCQUxDxcNMjIwNjE3MDAyNDIyWjAvBgkqhkiG9w0BCQQxIgQgyCDmNy5kR2T3NpBX
fNhzFLNQv4PmI8kFb6VIt1kqeRswDQYJKoZIhvcNAQEBBQAEggEAWu1sxXCO/X8voU1zfvL+
My6KXb5va2CIuKD4dn/cllClWp8YizygIb+tPWfsT6DvaLOp1jE0raQyc8nUexLXSlIBGF7j
GVWYCy4Oo8mXki+YB3AP1eXiBpx8E4Aa3Rq6/FO80fqrVmUTuywGnv9m6zSIrzEPFujpRIDa
QQfDEOktRcLvNPXHfipTBzR4VSLkbZbyJBdigEPFUJVIRcAoI4tZAUVcbwANrHpZElFMBgr6
Rpn9l5nu7kUlZqXbV39Mfv8WCzctaUyc+Ag311sfWu5s6XaX3PtT9V4TnQhbSWcvR9NgM+As
NqelVbdJ/iA2SeNHU/65xf6dDE2zdHDfsw==
"""

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.roa_pem_text)

        layers = {}
        layers.update(opentypemap.get('cmsContentTypesMap'))

        getNextLayer = {
            rfc5652.id_ct_contentInfo: lambda x: x['contentType'],
            rfc5652.id_signedData: lambda x: x['encapContentInfo']['eContentType'],
            rfc9582.id_ct_routeOriginAuthz: lambda x: None
        }

        getNextSubstrate = {
            rfc5652.id_ct_contentInfo: lambda x: x['content'],
            rfc5652.id_signedData: lambda x: x['encapContentInfo']['eContent'],
            rfc9582.id_ct_routeOriginAuthz: lambda x: None
        }

        next_layer = rfc5652.id_ct_contentInfo
        while next_layer:
            asn1Object, rest = der_decoder(
                substrate, asn1Spec=layers[next_layer])
            self.assertFalse(rest)
            self.assertTrue(asn1Object.prettyPrint())
            self.assertEqual(substrate, der_encoder(asn1Object))

            substrate = getNextSubstrate[next_layer](asn1Object)
            next_layer = getNextLayer[next_layer](asn1Object)

        self.assertEqual(0, asn1Object['version'])
        self.assertEqual(15562, asn1Object['asID'])

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.roa_pem_text)
        asn1Object, rest = der_decoder(
            substrate, asn1Spec=rfc5652.ContentInfo(), decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        oid = asn1Object['content']['encapContentInfo']['eContentType']
        substrate = asn1Object['content']['encapContentInfo']['eContent']

        cmsContentTypesMap = opentypemap.get('cmsContentTypesMap')
        self.assertIn(oid, cmsContentTypesMap)

        asn1Object, rest = der_decoder(
            substrate, asn1Spec=cmsContentTypesMap[oid], decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual(0, asn1Object['version'])
        self.assertEqual(15562, asn1Object['asID'])


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
