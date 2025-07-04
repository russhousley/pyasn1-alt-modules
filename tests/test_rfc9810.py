#
# This file is part of pyasn1-alt-modules software.
#
# Copyright (c) 2025, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc9810
from pyasn1_alt_modules import opentypemap


class CertRepMessageTestCase(unittest.TestCase):
    pem_text = """\
MIITuTCCARECAQKkWTBXMQswCQYDVQQGEwJUUjEQMA4GA1UEChMHRS1HdXZlbjEUMBIGA1UECxML
VHJ1c3RDZW50ZXIxIDAeBgNVBAMTF1JTQSBTZWN1cml0eSBDTVAgU2VydmVypC0wKzELMAkGA1UE
BhMCVFIxHDAaBgNVBAMME1ZhbGltby1WZXR0b3ItMTdEZWOgERgPMjAxMjA1MDMxMTE2MTdaoQ8w
DQYJKoZIhvcNAQEFBQCiIgQgZWVhMjg5MGU2ZGY5N2IyNzk5NWY2MWE0MzE2MzI1OWGkEgQQQ01Q
VjJUMTIyMzM0NjI3MKUSBBCAAAABgAAAAYAAAAGAAAABphIEEDEzNjY0NDMwMjlSYW5kb22jghIZ
MIISFaGCC84wggvKMIIFwDCCBKigAwIBAgIQfOVE05R616R6Nqgu3drXHzANBgkqhkiG9w0BAQUF
ADBxMQswCQYDVQQGEwJUUjEoMCYGA1UEChMfRWxla3Ryb25payBCaWxnaSBHdXZlbmxpZ2kgQS5T
LjE4MDYGA1UEAxMvZS1HdXZlbiBFbGVrdHJvbmlrIFNlcnRpZmlrYSBIaXptZXQgU2FnbGF5aWNp
c2kwHhcNMDgxMTI0MTAwMzI0WhcNMTYxMjE0MTExNzI0WjBdMQswCQYDVQQGEwJUUjEoMCYGA1UE
CgwfRWxla3Ryb25payBCaWxnaSBHdXZlbmxpZ2kgQS5TLjEkMCIGA1UEAwwbZS1HdXZlbiBNb2Jp
bCBUZXN0VVRGLTgtU09OMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzqaymRo5chRK
EKrhjWQky1HOm6b/Jy4tSUuo4vq3O9U3G2osOU/hHb6fyMmznLpc6CaZ3qKYiuDMFRW8g1kNjEjV
sFSvH0Yd4qgwP1+qqzhBSe+nCAnEbRUrz+nXJ4fKhmGaQ+ZSic+MeyoqDsf/zENKqdV7ea9l3Ilu
Rj93bmTxas9aWPWQ/U/fpwkwRXaqaONlM5e4GWdgA7T1aq106NvH1z6LDNXcMYw4lSZkj/UjmM/0
NhVz+57Ib4a0bogTaBmm8a1E5NtzkcA7pgnZT8576T0UoiOpEo+NAELA1B0mRh1/82HK1/0xn1zt
1ym4XZRtn2r2l/wTeEwU79ALVQIDAQABo4ICZjCCAmIwfAYIKwYBBQUHAQEEcDBuMDIGCCsGAQUF
BzABhiZodHRwOi8vdGVzdG9jc3AyLmUtZ3V2ZW4uY29tL29jc3AueHVkYTA4BggrBgEFBQcwAoYs
aHR0cDovL3d3dy5lLWd1dmVuLmNvbS9kb2N1bWVudHMvVGVzdEtvay5jcnQwDgYDVR0PAQH/BAQD
AgEGMA8GA1UdEwEB/wQFMAMBAf8wggElBgNVHSAEggEcMIIBGDCCARQGCWCGGAMAAQECATCCAQUw
NgYIKwYBBQUHAgEWKmh0dHA6Ly93d3cuZS1ndXZlbi5jb20vZG9jdW1lbnRzL05FU1VFLnBkZjCB
ygYIKwYBBQUHAgIwgb0egboAQgB1ACAAcwBlAHIAdABpAGYAaQBrAGEAIABpAGwAZQAgAGkAbABn
AGkAbABpACAAcwBlAHIAdABpAGYAaQBrAGEAIAB1AHkAZwB1AGwAYQBtAGEAIABlAHMAYQBzAGwA
YQByATEAbgExACAAbwBrAHUAbQBhAGsAIABpAOcAaQBuACAAYgBlAGwAaQByAHQAaQBsAGUAbgAg
AGQAbwBrAPwAbQBhAG4BMQAgAGEA5wExAG4BMQB6AC4wWAYDVR0fBFEwTzBNoEugSYZHaHR0cDov
L3Rlc3RzaWwuZS1ndXZlbi5jb20vRWxla3Ryb25pa0JpbGdpR3V2ZW5saWdpQVNSb290L0xhdGVz
dENSTC5jcmwwHQYDVR0OBBYEFLMoTImEKeXbqNjbYZkKshQi2vwzMB8GA1UdIwQYMBaAFGCI4dY9
qCIkag0hwBgz5haCSNl0MA0GCSqGSIb3DQEBBQUAA4IBAQAWOsmvpoFB9sX2aq1/LjPDJ+A5Fpxm
0XkOGM9yD/FsLfWgyv2HqBY1cVM7mjJfJ1ezkS0ODdlU6TyN5ouvAi21V9CIk69I3eUYSDjPpGia
qcCCvJoMF0QD7B70kj2zW7IJ7pF11cbvPLaatdzojsH9fVfKtxtn/ZLrXtKsyUW5vKHOeniU6BBB
Gl/ZZkFNXNN4mrB+B+wDV9OmdMw+Mc8KPq463hJQRat5a9lrXMdNtMAJOkvsUUzOemAsITjXWlyg
BULijBhi8ZmMp0W7p6oKENX3vH2HCPCGQU29WIrK4iUoscjz93fB6oa4FQpxY0k3JRnWvD5FqkRD
FKJdq/q9MIIDzzCCAregAwIBAgIQa34pJYdDFNXx90OkMkKzIjANBgkqhkiG9w0BAQUFADBxMQsw
CQYDVQQGEwJUUjEoMCYGA1UEChMfRWxla3Ryb25payBCaWxnaSBHdXZlbmxpZ2kgQS5TLjE4MDYG
A1UEAxMvZS1HdXZlbiBFbGVrdHJvbmlrIFNlcnRpZmlrYSBIaXptZXQgU2FnbGF5aWNpc2kwHhcN
MDYxMjE1MTUxMzU0WhcNMTYxMjE1MTExMzU0WjBxMQswCQYDVQQGEwJUUjEoMCYGA1UEChMfRWxl
a3Ryb25payBCaWxnaSBHdXZlbmxpZ2kgQS5TLjE4MDYGA1UEAxMvZS1HdXZlbiBFbGVrdHJvbmlr
IFNlcnRpZmlrYSBIaXptZXQgU2FnbGF5aWNpc2kwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCU/PTxSkcWPJMx4UO8L8ep9/JqRgAZ79EqYWgR4K2bNLgENpc5j0hO+QydgovFODzkEIBP
RIBavMz9Cw2PONpSBmxd4K1A/5hGqoGEz8UCA2tIx4+Z2A9AQ2O3BYi9FWM+0D1brJDO+6yvX4m5
Rf3mLlso52NIVV705fIkmOExHjdAj/xB0/LICZMfwKn8F19Jae/SQv9cFnptbNRCq8hU5zLRngpR
eT1PYrZVV0XLbzbDPwgzLXCzDxG1atdGd5JRTnD58qM1foC3+hGafuyissMQVGnBQFlsx7V6OdlD
bsxUXegCl2li0RpRJXLqyqMdtEplaznKp8NnbddylfrPAgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIB
hjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFGCI4dY9qCIkag0hwBgz5haCSNl0MB0GA1Ud
DgQWBBRgiOHWPagiJGoNIcAYM+YWgkjZdDANBgkqhkiG9w0BAQUFAAOCAQEAKftTVjgltZJxXwDs
MumguOSlljOQjotVVpES1QYwo3a5RQVpKuS4KYDEdWLD4ITtDNOA/iGKYWCNyKsE1BCL66irknZw
iR6p6P+q2Wf7fGYSwUBcSBwWBTA+0EgpvPL3/vRuVVCVgC8XHBr72jKKTg9Nwcj+1FwXGZTDpjX8
dzPhTXEWceQcDn2FRdNt6BQad9Hdq08lMHiyozsWniYZYuWpud91i8Pl698H9t0KqiJg6rPKc9kd
z9QyC8E/cLIJgYhvfzXMxvmSjeSSFSqTHioqfpU3k8AWXuxqJUxbdQ8QrVaTXRByzEr1Ze0TYpDs
oel1PjC9ouO8bC7cGrbCWzCCAi8wggGYAhBlEjJUo9asY2ISG4oHjcpzMA0GCSqGSIb3DQEBBQUA
MFoxCzAJBgNVBAYTAlRSMRAwDgYDVQQKEwdFLUd1dmVuMRQwEgYDVQQLEwtUcnVzdENlbnRlcjEj
MCEGA1UEAxMaRS1HdXZlblRFU1RDQUhTTSBTeXN0ZW0gQ0EwHhcNMDkxMTMwMjIxMzEzWhcNMTYx
MTMwMTkxMTUxWjBXMQswCQYDVQQGEwJUUjEQMA4GA1UEChMHRS1HdXZlbjEUMBIGA1UECxMLVHJ1
c3RDZW50ZXIxIDAeBgNVBAMTF1JTQSBTZWN1cml0eSBDTVAgU2VydmVyMIGfMA0GCSqGSIb3DQEB
AQUAA4GNADCBiQKBgQDCaZeJerGULW+1UPSu9T0voPNgzPcihXX6G5Q45nS4RNCe+pOc226EtD51
wu6Eq2oARpZmCrKPn63EFmHEE04dRDr8MS2LHuZK8xslIx/AvPnV568795EPoAyhGIX9Na9ZHhnI
zSPWmWfBd9bsQiLVF7C9dOvfW125mtywWXELewIDAQABMA0GCSqGSIb3DQEBBQUAA4GBAAiIse/x
aWwRWUM0CIzfnoXfrgyLdKVykK7dTPgoMJgAx229uN6VTPyk+E+lTKq9PhK+e/VJNNg9PjSFjKFd
lfSDOi9ne1xOrb7cNTjw+sGf1mfNWyzizLXa7su7ISFN+GaClmAstH9vXsRxg1oh3pFMJv47I6iw
gUQlwwg8WsY/MIIGPzCCBjsCAQAwAwIBADCCBi+gggYrMIIGJzCCBQ+gAwIBAgIRALGVtVAeoM1x
gjgOX3alZ5MwDQYJKoZIhvcNAQEFBQAwXTELMAkGA1UEBhMCVFIxKDAmBgNVBAoMH0VsZWt0cm9u
aWsgQmlsZ2kgR3V2ZW5saWdpIEEuUy4xJDAiBgNVBAMMG2UtR3V2ZW4gTW9iaWwgVGVzdFVURi04
LVNPTjAeFw0xMjA1MDMxMTE2MTdaFw0xMzA1MDMxMTE2MTdaMGoxCzAJBgNVBAYTAlRSMREwDwYD
VQQKDAhGaXJlIExMVDEbMBkGA1UECwwScG9wQ29kZSAtIDEyMzQ1Njc4MRQwEgYDVQQFEws3NjU0
MzQ1Njc2NTEVMBMGA1UEAwwMQnVyYWsgWW9uZGVtMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
gQCpfSB7xcsHZR4E27yGHkzUJx1y2iknzX4gRM2acyPljRw/V5Lm7POrfWIX9UF2sxfYfRqxYmD0
+nw72nx8R/5AFQK0BfjHxIc5W1YekMHF8PSORo9rJqcX+qn+NBYwqcJl4EdObTcOtMWC6ws6n0uA
oDvYYN0ujkua496sp+INiQIDAQABo4IDVzCCA1MwQgYIKwYBBQUHAQEENjA0MDIGCCsGAQUFBzAB
hiZodHRwOi8vdGVzdG9jc3AyLmUtZ3V2ZW4uY29tL29jc3AueHVkYTAfBgNVHSMEGDAWgBSzKEyJ
hCnl26jY22GZCrIUItr8MzCCAXIGA1UdIASCAWkwggFlMIGxBgZghhgDAAEwgaYwNgYIKwYBBQUH
AgEWKmh0dHA6Ly93d3cuZS1ndXZlbi5jb20vZG9jdW1lbnRzL05FU1VFLnBkZjBsBggrBgEFBQcC
AjBgGl5CdSBzZXJ0aWZpa2EsIDUwNzAgc2F5xLFsxLEgRWxla3Ryb25payDEsG16YSBLYW51bnVu
YSBnw7ZyZSBuaXRlbGlrbGkgZWxla3Ryb25payBzZXJ0aWZpa2FkxLFyMIGuBglghhgDAAEBAQMw
gaAwNwYIKwYBBQUHAgEWK2h0dHA6Ly93d3cuZS1ndXZlbi5jb20vZG9jdW1lbnRzL01LTkVTSS5w
ZGYwZQYIKwYBBQUHAgIwWRpXQnUgc2VydGlmaWthLCBNS05FU0kga2Fwc2FtxLFuZGEgeWF5xLFu
bGFubcSxxZ8gYmlyIG5pdGVsaWtsaSBlbGVrdHJvbmlrIHNlcnRpZmlrYWTEsXIuMA4GA1UdDwEB
/wQEAwIGwDCBgwYIKwYBBQUHAQMEdzB1MAgGBgQAjkYBATBpBgtghhgBPQABp04BAQxaQnUgc2Vy
dGlmaWthLCA1MDcwIHNheWlsaSBFbGVrdHJvbmlrIEltemEgS2FudW51bmEgZ8O2cmUgbml0ZWxp
a2xpIGVsZWt0cm9uaWsgc2VydGlmaWthZGlyMEUGA1UdCQQ+MDwwFAYIKwYBBQUHCQIxCAQGQW5r
YXJhMBIGCCsGAQUFBwkBMQYEBDE5NzkwEAYIKwYBBQUHCQQxBAQCVFIwGAYDVR0RBBEwD4ENZmly
ZUBmaXJlLmNvbTBgBgNVHR8EWTBXMFWgU6BRhk9odHRwOi8vdGVzdHNpbC5lLWd1dmVuLmNvbS9F
bGVrdHJvbmlrQmlsZ2lHdXZlbmxpZ2lBU01LTkVTSS1VVEYtOC9MYXRlc3RDUkwuY3JsMB0GA1Ud
DgQWBBSLG9aIb1k2emFLCpM93kXJkWhzuTANBgkqhkiG9w0BAQUFAAOCAQEACoGCn4bzDWLzs799
rndpB971UD2wbwt8Hkw1MGZkkJVQeVF4IS8FacAyYk5vY8ONuTA/Wsh4x23v9WTCtO89HMTz81eU
BclqZ2Gc2UeMq7Y4FQWR8PNCMdCsxVVhpRRE6jQAyyR9YEBHQYVLfy34e3+9G/h/BR73VGHZJdZI
DDJYd+VWXmUD9kGk/mI35qYdzN3O28KI8sokqX0z2hvkpDKuP4jNXSCHcVkK23tX2x5m6m0LdqVn
vnCx2LfBn1wf1u7q30p/GgMVX+mR3QHs7feGewEjlkxuEyLVVD+uBwWCT6zcad17oaAyXV5RV28L
vH0WNg6pFUpwOP0l+nIOqqCBhAOBgQBAtTB5Qd18sTxEKhSzRiN2OycFPrqoqlZZTHBohe8bE2D4
Xc1ejkFWUEvQivkqJxCD6C7I37xgDaq8DZnaczIBxbPkY0QMdeL4MiEqlw/tlrJGrWoC5Twb0t/m
JA5RSwQoMDYTj2WrwtM/nsP12T39or4JRZhlLSM43IaTwEBtQw==
"""

    def setUp(self):
        self.asn1Spec = rfc9810.PKIMessage()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual(2, asn1Object['header']['pvno'])
        self.assertEqual(0, 
            asn1Object['body']['cp']['response'][0]['status']['status'])

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(
            substrate, asn1Spec=self.asn1Spec, decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        found = False
        rdns = asn1Object['header']['sender']['directoryName']['rdnSequence']
        for rdn in rdns:
            if rdn[0]['type'].prettyPrint() == '2.5.4.11':
                self.assertEqual('TrustCenter', rdn[0]['value']['printableString'])
                found = True

        self.assertTrue(found)


class V3CertConfMessageTestCase(unittest.TestCase):
    pem_text = """\
MIIBRzCB7AIBA6QSMBAxDjAMBgNVBAMTBXRlc3QxpDwwOjELMAkGA1UEBhMCRkkxEzARBgNV
BAoMCkluc3RhIERlbW8xFjAUBgNVBAMMDUluc3RhIERlbW8gQ0GgERgPMjAyMTA4MDYwOTMx
MTNaoT4wPAYJKoZIhvZ9B0INMC8EEB5x3dQ4Vg4kdP1n+ap2w0swCwYJYIZIAWUDBAIBAgIB
9DAKBggrBgEFBQgBAqIGBAQzMDc4pBIEEMXyngikbmIqdUhd+jbxQ8ulEgQQngNAx7MofTIt
d+s/kKMkh6YSBBDkF9+tX9JjzPWnXS2sNZUiuD0wOzA5oA0wCwYJYIZIAWUDBAIBBCDhwnx/
3e8WA5IwTb9/KW1YPo8G4H6Y1d8QMWM9ZiqNvQIBADADAgEAoBcDFQCYMTqZTiG8dikDtNrm
H7/mZ0aOaQ==
"""

    def setUp(self):
        self.asn1Spec = rfc9810.PKIMessage()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual(3, asn1Object['header']['pvno'])
        self.assertTrue(asn1Object['body']['certConf'][0]['hashAlg'].hasValue())
        self.assertEqual(0, 
            asn1Object['body']['certConf'][0]['statusInfo']['status'])

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(
            substrate, asn1Spec=self.asn1Spec, decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        found = False
        rdns = asn1Object['header']['sender']['directoryName']['rdnSequence']
        for rdn in rdns:
            if rdn[0]['type'].prettyPrint() == '2.5.4.3':
                self.assertEqual('test1', rdn[0]['value']['printableString'])
                found = True

        self.assertTrue(found)


class CMPMapsTestCase(unittest.TestCase):

    def testOldCMPITValues(self):
        cmpInfoTypeAndValueMap = opentypemap.get('cmpInfoTypeAndValueMap')
        for i in list(range(1, 7+1)) + list(range(10, 16+1)):
            oid = rfc9810.id_it + (i,)
            self.assertIn(oid, cmpInfoTypeAndValueMap)
            self.assertIsNotNone(cmpInfoTypeAndValueMap[oid])

    def testNewCMPITValues(self):
        cmpInfoTypeAndValueMap = opentypemap.get('cmpInfoTypeAndValueMap')
        for i in range(17, 23+1):
            oid = rfc9810.id_it + (i,)
            self.assertIn(oid, cmpInfoTypeAndValueMap)
            self.assertIsNotNone(cmpInfoTypeAndValueMap[oid])

    def testRegCtrlValues(self):
        cmsAttributesMap = opentypemap.get('cmsAttributesMap')
        regCtrlOIDs = [rfc9810.id_regCtrl_altCertTemplate,
                       rfc9810.id_regCtrl_algId,
                       rfc9810.id_regCtrl_rsaKeyLen, ]
        for oid in regCtrlOIDs:
            self.assertIn(oid, cmsAttributesMap)
            self.assertIsNotNone(cmsAttributesMap[oid])

    def testAlgorithmIdentifierValues(self):
        algorithmIdentifierMap = opentypemap.get('algorithmIdentifierMap')
        aldIdOIDs = [rfc9810.id_PasswordBasedMac,
                     rfc9810.id_DHBasedMac,
                     rfc9810.id_KemBasedMac, ]
        for oid in aldIdOIDs:
            self.assertIn(oid, algorithmIdentifierMap)
            self.assertIsNotNone(algorithmIdentifierMap[oid])


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
