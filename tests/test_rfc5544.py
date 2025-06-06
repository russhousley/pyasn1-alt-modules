#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley
# 
# Copyright (c) 2021-2025, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc5544
from pyasn1_alt_modules import opentypemap


class TimeStampedDataTestCase(unittest.TestCase):
    pem_text = """\
MIIY+wYLKoZIhvcNAQkQAR+gghjqMIIY5gIBARYiaHR0cHM6Ly93d3cuZXhhbXBs
ZS5jb20vd2F0c29uLnR4dDAtAQEADAp3YXRzb24udHh0Fhx0ZXh0L3BsYWluOyBj
aGFyc2V0PXVzLWFzY2lpBCZXYXRzb24sIGNvbWUgaGVyZSAtIEkgd2FudCB0byBz
ZWUgeW91LqCCGGQwghhgMIIVaAYJKoZIhvcNAQcCoIIVWTCCFVUCAQMxDzANBglg
hkgBZQMEAgMFADCCAaMGCyqGSIb3DQEJEAEEoIIBkgSCAY4wggGKAgEBBgQqAwQB
MFEwDQYJYIZIAWUDBAIDBQAEQBrtQ2rsQ2Wb/Be5eBCiG0tNFONJlCnwVuQtIIhM
9LdczhwryuAPIvM8cFFxR7+KQCWRPrhYWfr+dx04Pay4zuUCAy/vnBgPMjAyMTAy
MDkxNTM2MTVaAQH/oIIBEaSCAQ0wggEJMREwDwYDVQQKEwhGcmVlIFRTQTEMMAoG
A1UECxMDVFNBMXYwdAYDVQQNE21UaGlzIGNlcnRpZmljYXRlIGRpZ2l0YWxseSBz
aWducyBkb2N1bWVudHMgYW5kIHRpbWUgc3RhbXAgcmVxdWVzdHMgbWFkZSB1c2lu
ZyB0aGUgZnJlZXRzYS5vcmcgb25saW5lIHNlcnZpY2VzMRgwFgYDVQQDEw93d3cu
ZnJlZXRzYS5vcmcxIjAgBgkqhkiG9w0BCQEWE2J1c2lsZXphc0BnbWFpbC5jb20x
EjAQBgNVBAcTCVd1ZXJ6YnVyZzELMAkGA1UEBhMCREUxDzANBgNVBAgTBkJheWVy
bqCCEAgwggf/MIIF56ADAgECAgkAwemGFg2o6YAwDQYJKoZIhvcNAQENBQAwgZUx
ETAPBgNVBAoTCEZyZWUgVFNBMRAwDgYDVQQLEwdSb290IENBMRgwFgYDVQQDEw93
d3cuZnJlZXRzYS5vcmcxIjAgBgkqhkiG9w0BCQEWE2J1c2lsZXphc0BnbWFpbC5j
b20xEjAQBgNVBAcTCVd1ZXJ6YnVyZzEPMA0GA1UECBMGQmF5ZXJuMQswCQYDVQQG
EwJERTAeFw0xNjAzMTMwMTUyMTNaFw00MTAzMDcwMTUyMTNaMIGVMREwDwYDVQQK
EwhGcmVlIFRTQTEQMA4GA1UECxMHUm9vdCBDQTEYMBYGA1UEAxMPd3d3LmZyZWV0
c2Eub3JnMSIwIAYJKoZIhvcNAQkBFhNidXNpbGV6YXNAZ21haWwuY29tMRIwEAYD
VQQHEwlXdWVyemJ1cmcxDzANBgNVBAgTBkJheWVybjELMAkGA1UEBhMCREUwggIi
MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC2Ao4OMDLxERDZZM2pS50CeOGU
KukTqqWZB82ml5OZW9msfjO62f43BNocAamNIa/j9ZGlnXBncFFnmY9QFnIuCrRi
sh9DkXHSz8xFk/NzWveUpasxH2wBDHiY3jPXXEUQ7nb0vR0UmM8X0wPwal3Z95bM
bKm2V6Vv4+pP77585rahjT41owzuX/Fw0c85ozPT/aiWTSLbaFsp5WG+iQ8KqEWH
Oy6Eqyarg5/+j63p0juzHmHSc8ybiAZJGF+r7PoFNGAKupAbYU4uhUWC3qIib8Gc
199SvtUNh3fNmYjAU6P8fcMoegaKT/ErcTzZgDZm6VU4VFb/OPgCmM9rk4VukiR3
SmbPHN0Rwvjv2FID10WLJWZLE+1jnN7U/4ET1sxTU9JylHPDwwcVfHIqpbXdC/st
bDixuTdJyIHsYAJtCJUbOCS9cbrLzkc669Y28LkYtKLI/0aU8HRXry1vHPglVNF3
D9ef9dMU3NEEzdyryUE4BW388Bfn64Vy/VL3AUTxiNoF9YI/WN0GKX5zh77S13LB
PagmZgEEX+QS3XCYbAyYe6c0S5A3OHUW0ljniFtR+JaLfyYBITvEy0yF+P8LhK9q
mIM3zfuBho9+zzHcpnFtfsLdgCwWcmKeXABSyzV90pqvxD9hWzsf+dThzgjHHHPh
/rt9xWozYhMp6e1sIwIDAQABo4ICTjCCAkowDAYDVR0TBAUwAwEB/zAOBgNVHQ8B
Af8EBAMCAcYwHQYDVR0OBBYEFPpVDYw0ZlFDTPfns6dsla965qSXMIHKBgNVHSME
gcIwgb+AFPpVDYw0ZlFDTPfns6dsla965qSXoYGbpIGYMIGVMREwDwYDVQQKEwhG
cmVlIFRTQTEQMA4GA1UECxMHUm9vdCBDQTEYMBYGA1UEAxMPd3d3LmZyZWV0c2Eu
b3JnMSIwIAYJKoZIhvcNAQkBFhNidXNpbGV6YXNAZ21haWwuY29tMRIwEAYDVQQH
EwlXdWVyemJ1cmcxDzANBgNVBAgTBkJheWVybjELMAkGA1UEBhMCREWCCQDB6YYW
DajpgDAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vd3d3LmZyZWV0c2Eub3JnL3Jv
b3RfY2EuY3JsMIHPBgNVHSAEgccwgcQwgcEGCisGAQQBgfIkAQEwgbIwMwYIKwYB
BQUHAgEWJ2h0dHA6Ly93d3cuZnJlZXRzYS5vcmcvZnJlZXRzYV9jcHMuaHRtbDAy
BggrBgEFBQcCARYmaHR0cDovL3d3dy5mcmVldHNhLm9yZy9mcmVldHNhX2Nwcy5w
ZGYwRwYIKwYBBQUHAgIwOxo5RnJlZVRTQSB0cnVzdGVkIHRpbWVzdGFtcGluZyBT
b2Z0d2FyZSBhcyBhIFNlcnZpY2UgKFNhYVMpMDcGCCsGAQUFBwEBBCswKTAnBggr
BgEFBQcwAYYbaHR0cDovL3d3dy5mcmVldHNhLm9yZzoyNTYwMA0GCSqGSIb3DQEB
DQUAA4ICAQBor36/k4Vi70zrO1gL4vr2zDWiZ3KWLz2VkB+lYwyH0JGYmEzooGoz
+KnCgu2fHLEaxsI+FxCO5O/Ob7KU3pXBMyYiVXJVIsphlx1KO394JQ37jUruwPsZ
WbFkEAUgucEOZMYmYuStTQq64imPyUj8Tpno2ea4/b5EBBIex8FCLqyyydcyjgc5
bmC087uAOtSlVcgP77U/hed2SgqftK/DmfTNL1+/WHEFxggc89BTN7a7fRsBC3Sf
SIjJEvNpa6G2kC13t9/ARsBKDMHsT40YXi2lXft7wqIDbGIZJGpPmd27bx+Ck5jz
uAPcCtkNy1m+9MJ8d0BLmQQ7eCcYZ5kRUsOZ8Sy/xMYlrcCWNVrkTjQhAOxRelAu
Lwb5QLjUNZm7wRVPiudhoLDVVftKE5HU80IK+NvxLy1925133OFTeAQHSvF15PLW
1Vs0tdb33L3TFzCvVkgNTAz/FD+eg7wVGGbQug8LvcR/4nhkF2u9bBq4XfMl7fd3
iJvERxvz+nPlbMWR6LFgzaeweGoewErDsk+i4o1dGeXkgATV4WaoPILsb9VPs4Xr
r3EzqFtS3kbbUkThw0ro025xL5/ODUk9fT7dWGxhmOPsPm6WNG9BesnyIeCv8zqP
agse9MAjYwt2raqNkUM4JezEHEmluYsYHH2jDpl6uVTHPCzYBa/amTCCCAEwggXp
oAMCAQICCQDB6YYWDajpgjANBgkqhkiG9w0BAQ0FADCBlTERMA8GA1UEChMIRnJl
ZSBUU0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAWBgNVBAMTD3d3dy5mcmVldHNhLm9y
ZzEiMCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNvbTESMBAGA1UEBxMJ
V3VlcnpidXJnMQ8wDQYDVQQIEwZCYXllcm4xCzAJBgNVBAYTAkRFMB4XDTE2MDMx
MzAxNTczOVoXDTI2MDMxMTAxNTczOVowggEJMREwDwYDVQQKEwhGcmVlIFRTQTEM
MAoGA1UECxMDVFNBMXYwdAYDVQQNE21UaGlzIGNlcnRpZmljYXRlIGRpZ2l0YWxs
eSBzaWducyBkb2N1bWVudHMgYW5kIHRpbWUgc3RhbXAgcmVxdWVzdHMgbWFkZSB1
c2luZyB0aGUgZnJlZXRzYS5vcmcgb25saW5lIHNlcnZpY2VzMRgwFgYDVQQDEw93
d3cuZnJlZXRzYS5vcmcxIjAgBgkqhkiG9w0BCQEWE2J1c2lsZXphc0BnbWFpbC5j
b20xEjAQBgNVBAcTCVd1ZXJ6YnVyZzELMAkGA1UEBhMCREUxDzANBgNVBAgTBkJh
eWVybjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALWRBIxOSG806dwI
Yn/CN1FiI2mEuCyxML7/UXz8OPhLzlxlqHTasmIa4Lzn4zVj4O3pNP1fiCMVnweE
iAgidGDB7YgmFwb0KBM0NZ37uBvRNT/BeWEK8ajIyGXcAOojs6ib5r0DuoWp7IJ9
YFZZBeItalhO0TgK4VAoDO45fpigEvOARkAHhiRDvAd8uV9CGvMXEtloPNtt/7rz
yLpbpWauUj1FnWF3NG1NhA4niGt8AcW4kNeKLie7qN0vmigS4VfWL5IcZZYlSAad
zbfQbeGB3g6VcNZvhyIM4otiirVZBvPuDCEPcFHo9IWK+LmpLQnkavLZy6W/z60W
jN9gRJGksGYDsRTK9wMfBl5+7vpTxXXzSQwFnS4y3cdqxNTExxBoO5f9G+WRvGEF
UYbYj5oDkbMHtvke2VTao2+azWoeFKouSt8XRktU2xjbtv/jAIAkZUc3BDbOTne6
5d5v4PP51uf/vrRh55TpL7CVH4quYaQSzOmyEHRjXIvjJ64aD2tKZG6w+EY7xjv4
RVMENdGegCUR7J9mw0lpUti+y2mwqk1MQfYFFf59y7iTGc3aWbpq6kvjzq5xjm/L
bM19ufxQuxWxLzZlsKowconC5t1LERzki6LZ79taa5pQYGkzT7NPb8euMw8LNCCK
rIDfMmb92QRlh2uiy4mNlQUxW257AgMBAAGjggHbMIIB1zAJBgNVHRMEAjAAMB0G
A1UdDgQWBBRudgt7Tk+c4WDKbSzpJ6KilLN3NzAfBgNVHSMEGDAWgBT6VQ2MNGZR
Q0z357OnbJWveuaklzALBgNVHQ8EBAMCBsAwFgYDVR0lAQH/BAwwCgYIKwYBBQUH
AwgwYwYIKwYBBQUHAQEEVzBVMCoGCCsGAQUFBzAChh5odHRwOi8vd3d3LmZyZWV0
c2Eub3JnL3RzYS5jcnQwJwYIKwYBBQUHMAGGG2h0dHA6Ly93d3cuZnJlZXRzYS5v
cmc6MjU2MDA3BgNVHR8EMDAuMCygKqAohiZodHRwOi8vd3d3LmZyZWV0c2Eub3Jn
L2NybC9yb290X2NhLmNybDCBxgYDVR0gBIG+MIG7MIG4BgEAMIGyMDMGCCsGAQUF
BwIBFidodHRwOi8vd3d3LmZyZWV0c2Eub3JnL2ZyZWV0c2FfY3BzLmh0bWwwMgYI
KwYBBQUHAgEWJmh0dHA6Ly93d3cuZnJlZXRzYS5vcmcvZnJlZXRzYV9jcHMucGRm
MEcGCCsGAQUFBwICMDsaOUZyZWVUU0EgdHJ1c3RlZCB0aW1lc3RhbXBpbmcgU29m
dHdhcmUgYXMgYSBTZXJ2aWNlIChTYWFTKTANBgkqhkiG9w0BAQ0FAAOCAgEApclE
4sb6wKFNkwp/0KCxcrQfwUg8PpV8aKK82bl2TxqVAWH9ckctQaXu0nd4YgO1QiJA
+zomzeF2CHtvsQEd9MwZ4lcapKBREJZl6UxG9QvSre5qxBN+JRslo52r2kUVFdj/
ngcgno7CC3h09+Gg7efACTf+hKM0+LMmXO0tjtnfYTllg2d/6zgsHuOyPm6l8F3z
Dee5+JAF0lJm9hLznItPbaum17+6wZYyuQY3Mp9SpvBmoQ5D6qgfhJpsX+P+i16i
MnX2h/IFLlAupsMHYqZozOB4cd2Ol+MVu6kp4lWJl3oKMSzpbFEGsUN8d58rNhsY
KIjz7oojQ3T6Bj6VYZJif3xDEHOWXRJgko66AJ6ANCmuMkz5bwQjVPN7ylr93Hn3
k0arOIv8efAdyYYSVOpswSmUEHa4PSBVbzvlEyaDfyh294M7Nw58PUEFI4J9T1NA
DHIhjXUin/EMb4iTqaOhwMQrtMiYwT30HH9lc7T8VlFZcaYQp7DShXyCJan7IE6s
7KLolxqhr4eIairjxy/goKroQpgKd77xa5IRVFgJDZgrWUZgN2TnWgrT0RRUuZhv
Z4uatq/oSXAzrjq/1OtDt7yd7miBWUnmSBWCqC54UnfyKCEH7+OQIA4FCKy46oLq
JQUnbzydoqPTtK04u/iEK9o2/CRIKR9VjcAt0eAxggOKMIIDhgIBATCBozCBlTER
MA8GA1UEChMIRnJlZSBUU0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAWBgNVBAMTD3d3
dy5mcmVldHNhLm9yZzEiMCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNv
bTESMBAGA1UEBxMJV3VlcnpidXJnMQ8wDQYDVQQIEwZCYXllcm4xCzAJBgNVBAYT
AkRFAgkAwemGFg2o6YIwDQYJYIZIAWUDBAIDBQCggbgwGgYJKoZIhvcNAQkDMQ0G
CyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yMTAyMDkxNTM2MTVaMCsGCyqG
SIb3DQEJEAIMMRwwGjAYMBYEFJFto9hg7MqC40vFnReT5+loh18UME8GCSqGSIb3
DQEJBDFCBEDfsIsOPj9T9QmGJ0lQfWTLNhtYUYTUOYPq8XHdZkU98bfAMUHqqiuw
Zaiuo9IRixrrl9TsVqVwkVj3x+g5mLgAMA0GCSqGSIb3DQEBAQUABIICAIjxyj2s
+gJg3zXUL7HO9+z3jRTwaBlSpaskxI5iVmqxK56brG7lzRPkQYfWxUEbVRuK+Yvw
lzjpOwkBPtSk+g+E+lh2qzEt9xuBzygWuYqZeLGOHzsrp0PP9dvxfyfOuL8z/hgb
to4zJb8fJC2PShXdnPYaVntEkZvP5IFbOVeoce71V+c4mhFP1BBOnT0XkiNaV3V1
/0woxHwkD1w8WHLDtTejgCL1dm/6rT+hyMftVWPzspxbf+2pnhYZGpeu74fkG2H2
zcPEZE8OWfupBkVPu04Y9mBCWPY1Jeyh93IPCXBVhMxUhRlYlVdpYyV3DxOtW7G6
oUgsjEl85Y3pGTc9QzLaQYGtdirrXvq4Hwp0Tw73kNxidPAs3BmWQ68dULyFlJjb
/tjN+GyJDx6ftCGNb1BLyL4YlHQinuOr37GxdzPwAa1csEVlgc1ZFqlQOeKOJJ0t
BrTniGY/kEooLH3zVf2NopRWZnszgZZLi9DdhYVFlzchoK/3DergKfHY4RvEvMOV
TQKTgDc0sqpHlpwU8M9qr1QC/aspG8qWfCcx3GAcKK1ngXbxGXAlSVpCth5ggJT3
AUpFbyfsF5eq3tsl5f7pH7JYzf4KmO6sx/QdTe5D4NJUedc2l72Wq++Ebb/3XqEu
9xfcXsOfUpgWsV691UXpKIjQycEKRd5TIv1lMIIC8DCB2QIBATANBgkqhkiG9w0B
AQ0FADCBlTERMA8GA1UEChMIRnJlZSBUU0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAW
BgNVBAMTD3d3dy5mcmVldHNhLm9yZzEiMCAGCSqGSIb3DQEJARYTYnVzaWxlemFz
QGdtYWlsLmNvbTESMBAGA1UEBxMJV3VlcnpidXJnMQ8wDQYDVQQIEwZCYXllcm4x
CzAJBgNVBAYTAkRFFw0yMDAzMjIyMDE4NDVaFw0yMTAzMjIyMDE4NDVaoA8wDTAL
BgNVHRQEBAICEAAwDQYJKoZIhvcNAQENBQADggIBAHeOBgUbAkWJHJttPeW3ldH+
im6LtMjCl+UnV55q9PbiWmAljmAWKP4KVy0pSFULBybfUCZG+5yfyfst2zr9nrw4
5NSGR/BhMHsS/DrLl5BRcnPy6BpNy+1oQdUNH+fPDeHt61wWb27wdbDbpVh7Bkxi
jCLwIlRlbg6Lhom5wVXyGUucWEcppJVaNciclAJ+GgugQuCb1MWIlnMTGz9paOmc
Q/cr/s3EqgqIaynaF1jgUpBDVX0NCOcYRuxkT+kcyUzuE8i3dPzBNDxyBbCBRVdn
5HZ0HJO9rH2MzMkRAwSuXK0A0VShPV4x1+Lg74Feov5kMmSxnFMoOGxMOw/QibAN
Sot92snqO27C3xdO/GUV3kVXe4lHo1boCViAmTHz50li7oVbSEVnWn7THMWJ3KeY
H28fQlvx48G8QPtnG0YHF6oIo/D+aCBKoFDBFQegEwlVYvQHQTlbsX2uCwb5+zo8
qLOtaoxBmPMKAXGr26Y81qg1O3ucMERKN4Ai9ULWQZWF2k+Lfmct+E0EoffAaZYg
ipxGiUWhSeuOeOdhx31qRNOQ+s8QsTfUxWJsXXhSKDqCMbqudPFOX2uezWOM5HiG
5MQhib9K8pmPPdQ28/P4KizI2ChgF27XpQOJPUlemsxYjgXWhja5IU4VOGHljMFX
1sHIAb6+XAlE3qwTEWcw
"""

    def setUp(self):
        self.asn1Spec = rfc5652.ContentInfo()

    def testDerCodec(self):
        layers = { }
        layers.update(opentypemap.get('cmsContentTypesMap'))
        self.assertIn(rfc5544.id_ct_timestampedData, layers)

        getNextLayer = {
            rfc5652.id_ct_contentInfo: lambda x: x['contentType'],
        }

        getNextSubstrate = {
            rfc5652.id_ct_contentInfo: lambda x: x['content'],
        }

        substrate = pem.readBase64fromText(self.pem_text)

        layer = rfc5652.id_ct_contentInfo
        while layer in getNextLayer:
            asn1Object, rest = der_decoder(substrate, asn1Spec=layers[layer])
            self.assertFalse(rest)
            self.assertTrue(asn1Object.prettyPrint())
            self.assertEqual(substrate, der_encoder(asn1Object))

            substrate = getNextSubstrate[layer](asn1Object)
            layer = getNextLayer[layer](asn1Object)

        asn1Object, rest = der_decoder(substrate, asn1Spec=layers[layer])
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertIn(b'come here', asn1Object['content'])

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(
            substrate, asn1Spec=self.asn1Spec, decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertIn(b'come here', asn1Object['content']['content'])


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
