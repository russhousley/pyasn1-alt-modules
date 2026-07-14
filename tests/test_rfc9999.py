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

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc9999
from pyasn1_alt_modules import opentypemap


class RATSCMWJSONTestCase(unittest.TestCase):
    pem_text = """\
MIIFxjCCA66gAwIBAgICB+MwDQYJKoZIhvcNAQELBQAwRTELMAkGA1UEBhMCVVMx
CTAHBgNVBAgTADEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzETMBEGA1UEChMKQWNt
ZSwgSW5jLjAeFw0yNTA0MTUxNzE1MDFaFw0zNTA0MTUxNzE1MDFaMEUxCzAJBgNV
BAYTAlVTMQkwBwYDVQQIEwAxFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xEzARBgNV
BAoTCkFjbWUsIEluYy4wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCy
ACy3yS0afuMc/j0vmrkPAEvbWjMEqQEo+Ozw9K/Hu2m3kBMjPuFqZP7KYuQAoeym
8zXg4eyOkDXVI80Q0gmKeZ+lFOad2i6rjAxr+KsmJeZyIdCaGXuhpATGD/NPOMmN
cSRvp5eTce1IoEvH5DvOPdU1ugUkRUa48kqP/U8TIl1b4Tma7zGfOfHdVmACA37r
YqvgxkEQi32gYUp4OWUmKCjpMiEeDsvBrGABkYrWWy7HMDv9HpvxYYbYO6D9Awp9
v5H+gCELGjnEdaxIv88G76LzkDViGnCslhSuujOiC2Z/RvqKN96hWx7+tzw6kFoM
AqTt5XNEAtPweVfcTYQYiUfkgBhcj0yTxTXc2Va7d1EK7y8evOfRsxkOF7NNso4d
2xLL68szdvU7+jcMXoO3IYqcECIt1myXGf0pDYCkpNEwU0iMl7ens5y8Xy83O1zy
JTZ5LwDvxnCkdPzlSqaVxoIND8ciLXztalGWklf2rzsUImOu7TkeAHUPXHcT9Eva
NWFrwTS3cGqf0jQkZDs6NR9cJ01WMhK8oWUBJdrTjAHWut5ZeshThuBscQOSVtzr
kcI/1Sxzpt1XLs6wyQ/T6TQnJ9+DpHV5sZg4c1o/WMF2EIe5qhr1o7nTqhIwZ0Ty
Z6sBaars7SCTZPsX0ygh254hLGS3Ky3FziaT6AqCFwIDAQABo4G/MIG8MA4GA1Ud
DwEB/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0O
BAcEBQECAwQGMCEGA1UdEQQaMBiHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwWAYI
KwYBBQUHASMETAxKeyAiYSI6IFsgImFwcGxpY2F0aW9uL3ZuZC5hIiwgIllRIiBd
LCAiYiI6IFsgImFwcGxpY2F0aW9uL3ZuZC5iIiwgIllnIiBdIH0wDQYJKoZIhvcN
AQELBQADggIBAH1S7fcJPH+Nq8W/cyei/msuWjrVMSJ9TkbPSckJi+nqttlM+B0k
T7g7D5t7mPaZlIS5ucZ3c1pFnb320dOa01IcG1ean6PTcNp9hVyMU422Gt5OT9Ry
3rZrQleGINPdyfl//xjfkkxq8z6NmLR/7cB5pn35Ya97ludg1Xt6O3QiGTOzA57O
d595VbjPpyCXPtxYdYHqGiJtBpCct7Y2bqRdnGnlV1vkOhl68brS4zTmDFRoOGdd
IpG/8/0V5+hYmGfjHBLdNmk3Ieeu/Q3nkG0RhBXiGKcQjnOP7TBeVBflYoa2tXIv
QijdG4pEWu2EuzvpVAOq80M74wfHXrdXChCT1aIOikvebgcCAmCEhrxjOCC3EFCl
zvUo5qlSZZNogfnWDIk5nwLnB7qgOYoGmg5GbGzZGuYgGVuvMVKA4FW6YAr6BnLx
VbUuq9WAhI+gpmSw1UUQlAot8BtNbJMUfz5QR6dZIyWEr9Yy5mZlC4A6qhYqhuc/
ama3RhHUbIOIyn6Xp/WAopnlHTGrbGFrNm7gESNWSYYk0w259CTFNm2xFVaJtbAR
i8MWrN50R2SvOeFxnAxtem6GaBwYD4CuxhipiNIaXgqqItb93C661503i/tpoKYo
YM0ck9/UPsrxpfBq2OxE7IfXb73yKc8I8TYCY7VygDcx56Aq3I556qYR
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Certificate()
        
    def testDerCodec(self):
        certificateExtensionsMap = opentypemap.get('certificateExtensionsMap')
        self.assertIn(rfc9999.id_pe_cmw, certificateExtensionsMap)

        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual(2, asn1Object['tbsCertificate']['version'])

        found = False
        for extn in asn1Object['tbsCertificate']['extensions']:
            if extn['extnID'] == rfc9999.id_pe_cmw:
                extnValue, rest = der_decoder(extn['extnValue'],
                    asn1Spec=certificateExtensionsMap[extn['extnID']])
                self.assertFalse(rest)
                self.assertTrue(extnValue.prettyPrint())
                self.assertEqual(extn['extnValue'], der_encoder(extnValue))

                self.assertTrue(extnValue['json'].hasValue())
                self.assertIn("application/vnd", extnValue['json'])
                found = True
        
        self.assertTrue(found)


class RATSCMWCBORTestCase(unittest.TestCase):
    pem_text = """\
MIIFszCCA5ugAwIBAgICB+MwDQYJKoZIhvcNAQELBQAwRTELMAkGA1UEBhMCVVMx
CTAHBgNVBAgTADEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzETMBEGA1UEChMKQWNt
ZSwgSW5jLjAeFw0yNTA0MTUxNzEzMjBaFw0zNTA0MTUxNzEzMjBaMEUxCzAJBgNV
BAYTAlVTMQkwBwYDVQQIEwAxFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xEzARBgNV
BAoTCkFjbWUsIEluYy4wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCj
I2bnPeCCS/gS7Wbbrm6qIFeZDJ8505zAc827NIQfz8g5PIcPb7iFyyj6UqhjGrab
iq4IwiUGlFQAaaW8oIWrSeD2xArTxo/ccxZW4nckNjqK+hR0JS464DTsZjVpAIsq
t0S5/pvKfFIgIBFo5KxlhvGa0lgUbKj4X9Cppa2uzFg+8YtR0pHFPcpt5jqxGkPc
pj2uVCr1KjaI3/cnzrb7+lPrzkuxqujVsvLYYmq8DX3wrIrR/vrBEIcnEN9Ts95y
aJ+noIWQObvtUpk5RsrmuDbX+k8lX9laQRC0eyoTqPVuQ/NqN+Qo8swOmZiHNOmP
AS8EiOVet0OK1Y9s24Z0VxylazLvryF8ZVuikkMl4EuzEwZh3mxNlwXpjoDduv63
K+3985Ne7jtlSs9a3BEYLRiLfbq1fLkW6arl2ygZ+lNy1muxk5l9gpRMkMhrRy4D
R/qy5h9r4C51V9vE6LDxxQ5Wf6eFFIxGF7hLka3+UiigVdo5PC3+ZTv9LxX1bY6V
fKEQuTFjm7gXWX2Q+6A2J9OFdjOk5Xh7CrtRPLCyrSf2ahOyM4J7SM/HpC+GalLI
BudDjUn/w+gqNrGEFwYwnUjCGostTZBaoZEgwV5lUt0IjMORSDt85wu8qXsib8SR
Kq2KBqphceWy6p6lXQooau7+EzhQMjuwM9mtQO+RSwIDAQABo4GsMIGpMA4GA1Ud
DwEB/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0O
BAcEBQECAwQGMCEGA1UdEQQaMBiHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwRQYI
KwYBBQUHASMEOQQ3owGDdGFwcGxpY2F0aW9uL3JpbStjb3NlR9KEQ6EBJqEDAtpj
dHYyRCNH2lVhc4IZdTFEI0faVTANBgkqhkiG9w0BAQsFAAOCAgEAXYYSom5Q8ITK
nAW5LMQRdmsZCgHdQS6gCX6p9XNjXiTIyOgm20tzWKSKnGpE8xCpjJEVcDxeeJGU
vEUbTd4d3ghfTyDXULU1Z/bHeONw4+fyCI2P645vutnxCSPsnTHfEGU1am8peQ28
ahxOS4li5TWsVYbHif1IMymaabbW7GyEtiTztncP9va4LDFbVw+qjlui1yKJCukh
aCWs7NYfOEfP6K2xxnf3G0SO37g7RvSy1Ut9gkdmdkJ3nDm3s1tqh/bLU6wo/oYE
HcZKp05orrezpU5tEUFYZS3DNtW9HR771bPcJhX5s+w1y2/3H+aIzWk+6f+9E0kA
v0K3zbLxPURP4jVysUeYkIhYrffEwKCGN6cvX5/jUAx8QfLZzIVgZVBQjvEsXs1y
q24vq9ISiDfamQqpL997Uku1u0VqKk+3aXWHetD5OXz/+hjhZ5uS9bup5ubFRbsq
VGjEmFvhO1Y88ZGSBbu7JBGGK1lCShurPPg3geIqGKSE3fSUEy1aIgurJLIs9zOI
7dSUW25rmXQH4zdY6hw8gbqwvsthdNjpPkMGOq0aOYSnrTJluyV2BiP5xX4YTxhv
lvHLsAGxBNHQZzxBTkrTxtgCiDqSSdMPEdC77qxMbJymtx725Wva5ixPhcUKe/Mj
NO4j1OF/zGQtAWij8ZBmq0pCa7oJX6E=
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Certificate()
        
    def testDerCodec(self):
        certificateExtensionsMap = opentypemap.get('certificateExtensionsMap')
        self.assertIn(rfc9999.id_pe_cmw, certificateExtensionsMap)

        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual(2, asn1Object['tbsCertificate']['version'])

        found = False
        for extn in asn1Object['tbsCertificate']['extensions']:
            if extn['extnID'] == rfc9999.id_pe_cmw:
                extnValue, rest = der_decoder(extn['extnValue'],
                    asn1Spec=certificateExtensionsMap[extn['extnID']])
                self.assertFalse(rest)
                self.assertTrue(extnValue.prettyPrint())
                self.assertEqual(extn['extnValue'], der_encoder(extnValue))

                self.assertTrue(extnValue['cbor'].hasValue())
                self.assertTrue(extnValue['cbor'].prettyPrint().startswith('0xa301'))
                found = True
        
        self.assertTrue(found)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
