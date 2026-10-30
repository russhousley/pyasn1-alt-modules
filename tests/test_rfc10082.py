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
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc10082


class CompositeSignatureAlgorithmOIDsTestCase(unittest.TestCase):

    def testCompositSigObjectIdentifiers(self):
        oid_num_list = (
			(rfc10082.id_MLDSA44_RSA2048_PSS_SHA256, 37),
			(rfc10082.id_MLDSA44_RSA2048_PKCS15_SHA256, 38),
			(rfc10082.id_MLDSA44_Ed25519_SHA512, 39),
			(rfc10082.id_MLDSA44_ECDSA_P256_SHA256, 40),
			(rfc10082.id_MLDSA65_RSA3072_PSS_SHA512, 41),
			(rfc10082.id_MLDSA65_RSA3072_PKCS15_SHA512, 42),
			(rfc10082.id_MLDSA65_RSA4096_PSS_SHA512, 43),
			(rfc10082.id_MLDSA65_RSA4096_PKCS15_SHA512, 44),
			(rfc10082.id_MLDSA65_ECDSA_P256_SHA512, 45),
			(rfc10082.id_MLDSA65_ECDSA_P384_SHA512, 46),
			(rfc10082.id_MLDSA65_ECDSA_brainpoolP256r1_SHA512, 47),
			(rfc10082.id_MLDSA65_Ed25519_SHA512, 48),
			(rfc10082.id_MLDSA87_ECDSA_P384_SHA512, 49),
			(rfc10082.id_MLDSA87_ECDSA_brainpoolP384r1_SHA512, 50),
			(rfc10082.id_MLDSA87_Ed448_SHAKE256, 51),
			(rfc10082.id_MLDSA87_RSA3072_PSS_SHA512, 52),
			(rfc10082.id_MLDSA87_RSA4096_PSS_SHA512, 53),
			(rfc10082.id_MLDSA87_ECDSA_P521_SHA512, 54)
		)

        for (oid, num) in oid_num_list:
            self.assertTrue(oid.prettyPrint().endswith(str(num)))


class CompositeSignedDataTestCase(unittest.TestCase):
    pem_text = """\
MIIOxQYJKoZIhvcNAQcCoIIOtjCCDrICAQExDTALBglghkgBZQMEAgMwVgYJKoZI
hvcNAQcBoEkER2lkLU1MRFNBNjUtRUNEU0EtUDI1Ni1TSEE1MTIgc2lnbmVkLWRh
dGEgZXhhbXBsZSB3aXRoIHNpZ25lZCBhdHRyaWJ1dGVzMYIORDCCDkACAQEwXjBG
MQ0wCwYDVQQKDARJRVRGMQ4wDAYDVQQLDAVMQU1QUzElMCMGA1UEAwwcaWQtTUxE
U0E2NS1FQ0RTQS1QMjU2LVNIQTUxMgIUW0MoLO0np7/Ch09mfDIxAm9wH3AwCwYJ
YIZIAWUDBAIDoIGJMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcN
AQkFMQ8XDTI2MDEyMTIwMzkyMFowTwYJKoZIhvcNAQkEMUIEQIjYc0f2iK/i/r30
83ouERXhQHSSXulhH8t6jiLSUlMK6EbW5xNFsnRLbVI9PYdOvhVLqKaooVBrbVvx
iZPIX00wCgYIKwYBBQUHBi0Egg00EkQcFLL9GAh5+6zNBEQDr4xPJjTZjEgwgf0E
5kXiNLtzPJ0GMzrL/cUJz8LMhEEm1HMtLDWc3JOwSH5s5WyFRNSr9jhbDcwzHFDd
dZO3mAFBibQphfec+yU4E5CtDwBKR1yL0s4FjAQ2PuXVqRoxBy2z7fxCGrksY6C7
Zpesxy65vqnkTKmc2FF8D97Y+VsySeACY+3ZzTDZ1jEIApTzqqTiKy5mLpHeJ002
b4tdTtVdXa7JZT2bKlQwtSwOVnPEPfViCbCBklaH0K8oo+fGst6Xq+vd41V+XrLp
rPwned8k9ck8zJZq3YfVXzYxTwbpBjMiMyaMch0fs+umxe1ItgFZ3fJ5pI7Shiw+
j2ec7W7w1fmsXzF0ltk2wDwxIZF8g0qAiH3SOx7Gs2hfQnb0V9zhbjPt2NHiTM7r
QTTwvdPhxDQWl8uBcasPxOIDHnjrlcveghpXWgtSJAVm4wCTK55PXBshE2jFtbcC
xwXenC2pds4eH8J+zNwUeL9VTZg+l8WkXHvai7aFMlaWBSZK0fceBM/rIwAOP1gL
pBaurCr8nRxcjV7OKVDoRT+mEFPAjgk6Egyz+N1Pn8rjsY89aVizA7yIZmPU8qbG
BkBCVoJbqWYaHFY1wS+qFB9dIdOXK6rvqx1PO3yaAn8Yy1Sg3Wogie5m23hqysB+
j+G/VFwTBVc4DZTBPaHI7sPLEgCJGVX4saGhWjY7uUbK6VXTZxWrBmXUS3nka7OV
ZERgaIXlIBNYDEPAEClj6l4/WXhZOcA1HlnxEwvr+/4XyTWuOv9jFZL5W7qb7sEw
ug17x7xFVd5YZHvQtWkizGgAKjQj7oMjdF17vbnrTgowCOUpSnlCjJrWz5qst3r8
Mnjr0mFwv1Yv9S06EcCY62Bmks0eElfwwZAv8Je2IVtTidPft7AtdCg1o5Fjz4Ts
n4FbJ/quccY5e0g3FHjSRMXepW2nSov1yQuA9M+KNi0fllJLQDMg2yY3g7j5QReN
S1ue6/A2i0wsFLaRLOWsLyF0lZVf1VdLxI2UaxwQQOREHb9EXI4mgVKX76vyrvt1
tWO6yYlsNPeQ5+f4QiF2KSYo7/Gysb6fjOuLfT1s2mysefNNVSLXsfGM5ZGoSh1l
2veiQsLEGGqQ22b11ICzrzkzbCiM1SLFC41/4Dr8d0R/cSCEBAkOG0m16lHbkt16
J169myt5mBljy3s5QnRYEJqAFymimWerSsgwS/N8Mhem71QbM/0CZLHIXx1H91dO
dW9ZqLUfkuzN1RInouGNKPG7sW84eSWqrwc1JD4AKSs3lZQ+pUgF2DDl04Lc4ZN+
qjM5lTsuax5G3ywhfTvZVaKJL79u7f/2Wt9hZRNqc8NbsxkIpZ4HDrkclSJ6j/f4
C8fbhL5meVLHZ4dl2ZoVxcvQGNFA2NQMwlc3dlaEwRWDr4Mz8vTeBENt0Pzd5aW6
sLUuG3KWf95ONJFj0maO50RMPCRe8gnS/A2gR3tVp0+BVuJeD0DV8qGtaZScrtXr
eVRnvbeSfE5lxmOxji1UZ6rKxxQuzXjM8bY42fNqOktERXPCPewG+mBYfo0L+M1v
dmeRo4YKfye6HqeVBoVB7uIzB4TlGgFSMI+aLEYU9+lvXxbn9XxkKqj/Nxkuo4qi
qqmqO95Fpwhb86OmfJQ0xpR1d0o30eGysaj0Ii7u5VT5ni2gJCvblgL26QT8KfbL
pvEYZbq7RbsB/cbd9ldkAwVuTNkRWmyxeLr8SWuO7Uk3okAkJKTFn4zXUwUrgHLO
lH0xkfsWTvZBGqTNOMkc5hLeZnticjd4Agn60dMgybWWZ0NOl50xgwTbtZlh5dV9
xr6+CVZmYhAcB1srIS+4HF37KHm0O+c7bUDXvzGPNyt2DOz1UcnrJBcIhDU1iLvL
Yu8FMAdKlncqMRcO2C3KgpqpRMKQrOnwSuPqPHfiFAIuB2gdUDn1ob/+XqZ4UANR
nZHmXfn+n2bH+eT8EcEZ1XjeLyFeyJHRDR0aZyE0dKJyVA9a569YwHQYTpKVMEPp
9RtolkNBlMZYpQwvwhlg1Rcry4v6WamXKaagbOc3QQ48nNdZIyUFTiFAhGPReABe
uwVTUhFFNm0hqzcy7AKohg6ZPhYLdxrkfR3Q0bjMZvs6rqa17VvyzxQt0HDgZCJO
9H/X1BsOBnYlpjcnoU8WLPPKgOE/Nfvtipx8pC2V5Iq5v6ui7jHZ6G1TobI1x7ar
OIm5+nR0gS5R7gWx1UH4esEaVGDxkLOkTV1kxwq3BzRnl2LUrulod1sLVu1y/mVP
+g/uBq+G3lTWj486rTVCvqWj+P7iZXgsESobx7kMNlvCTeDaUPdAf4w0UHAa0tBH
eEkH0Piz08/iaWHD0uZ6tkQ1OpY3GxmWcvqol541X3EXJ5pdQA7DUz+2+KwqvzcN
wU799hOjHnxOXWc1+BWNVW4M4T/L2Y07+CW7KaKvH6Tq434aWeD0VhfuYCVioW7F
XO2yS9amsCuCcaw/nxSbMmdTEFt65ceLo22q57TtugbQCS5gECZKqA2vcyEKs+gd
Dx1HGS/9O3Xf9VpYvEaNW5NZib044A3gXRZbq3ndN2cZyUo3FF/XwsfPXrarBZug
xw7vnbdmdKkLb9Ig5nT0ZXZQV9cK5e6iUfbWR3s6+LvGPqSbiA1DQLM5A0tdybCD
yOBvuvTRsBJqUe13D9ypFnp3rut1LWdf8ZSxXVCwQVVGjyT1S//AsHVvGNGFQ8WD
U07fl37Qc9CD/HK12mdBRv/QQw3iMAD5hxHmz74bGIKmuNmsPPtcs/Itfmxovsuj
cPgwHsah8KgdSQv2somK9tx/Ba5iC9nLtm8DV3BPpUx55sv23lvVO5T+5PHl+XAK
TYedCVBsEfsQK4RlMbuRx3kFHO9FKGun/vAzEqxmTGr6alWmAtoyLJ7ZDEXrTZK+
ELduqCvwIHZ5Hoh6HzWLPzDma+JMK5X/BBVpKoBu0TvQl8x59En1+NYfHFFcl1Mi
jkQDHGlB56LBMXtwyJDn6iG52skJTzdNsFh3V4CgJSC8HXrmefPws1UGt0uXVNBC
EMUmSZTGBIA0Uw8tLBW9rBbklbBE3q+nU6fKASE4Yq2t+9eU5rLnMT51xfuXXVxD
KPBU2M0XPYJKVFwUIqa5KX4cJiMNnfupIVHZA1JXrz5tXNFmUhQcbtMl9sWBdPE+
vKwAnToBD3JYI68CURKGb8nkxJLT08Psmjz9gqYWJSJxlUyLsaCbrYz8vWivSFBn
cGw2hOYpwrmvwNrK+JehlcflRO3EPcUJYI7NRHt8soSV4J6LhrAWWXjQJKu7D12P
4KAStIulBHsyDbVm/Wm6lYbYnGOSWih7zxMhdNDU0tvls1whpZg3fod6mJ6crNcP
tKUjmlSf/MGrfsstwW7LiMwvkerA5HdhTLA9tZp+WmqJ9LSRhTOkXFlQwnZFlN3R
UVUIysYdH8qi/OjNdvDh0xp7Kanf1bIquMTPbg5sdJNKCVUjYLZ21aP3D2vHDDW9
CrN3KcFgd+uQUaEvWdr0VgJaK8VNFtH+5jZOdPyQjJGy2Gp4t53FtELeaQtNZmbC
mL07uESIO78AoDXdVN+G3q56OoaYvhAkOjUXnqTxlIyRpRrZycxg3yqYwKRrMkWs
EoqWdmqh8zsInNTGYsAdo+Dol7pY9Smk2nMVPRZHTDCmoNCdezrzFN5K0RydBwMK
ozvfSkBEkW7UqahNU3BhtpkBX72YYcHMYWMZNI77rYWRDjL99c9rMQ9LRuynYGF5
KD2jMf9NLkelelJ8g93JTRY1AdKs1viOvQ3j/lLjuen8B420Pb0ueLJSiQr+dego
C+jN4qM4auC4W+zwxxbnTviSUDPPxKGSIEFrLrQqVfxqUrXI/KYB1KgLl8Se4p50
Ho/58ZYcr3kKuAJ8QVJAX0cQCyqio9jyJUZDb9Cc85GNp61B8UghTqfgOReuFAd8
dvXz20ZLfTxXghljKrv/bWRSjVF2X7hLihOiaNQJAgx+pFXaehh5lTdFckUMDzLU
1J8ktL6m6VhcdRh9enogOLkvr4DM4o/1j48fIgPIurtYX+kKuxWRL088y7wsU4np
awjk+6c8Uy7q4NdrhuwME1fBeRy1LxsAaMMK2M8ONTIriCgbQnJfEN4WL0ir+iqB
wb5hzXLqXJlxz1Wnfs5ZR9L3OhQ1h9sIeihfFfNWnoLlF0q2pMnEMgLv+Mcbx7xQ
ZFCjOjnWQEKedzt9jM+V+Nql1nQCdZfnfgm2AvnCWLyeqID4HT1wV0mvWyLKFSto
SmjV2pEFxtYGftq12sD68w2VzBzn1SyGSwTva0hFn1KntRoVGXjAi17V9i3lrgCU
wrbiH8QjLdbX5wAab36iusocbo6Wve3zQ2yd0uwGFihITTk8VX3d7/QAAAAAAAAA
AAAAAAAAAAAAAAAABQwTGB0kMEUCIQCutiFHcWBuVepcqbpkStOw7ngMGdeqAx4P
pWoMuOAdkAIgXpG9PLXn/nqA6YMPvNnIi7zQDA3ucqzgF7pkjMN+CrY=
"""

    def setUp(self):
        self.asn1Spec = rfc5652.ContentInfo()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        save = sys.get_int_max_str_digits()
        sys.set_int_max_str_digits(0)
        self.assertTrue(asn1Object.prettyPrint())
        sys.set_int_max_str_digits(save)
        self.assertEqual(substrate, der_encoder(asn1Object))
        self.assertEqual(rfc5652.id_signedData, asn1Object['contentType'])

        sd, rest = der_decoder(asn1Object['content'], asn1Spec=rfc5652.SignedData())
        self.assertFalse(rest)
        save = sys.get_int_max_str_digits()
        sys.set_int_max_str_digits(0)
        self.assertTrue(sd.prettyPrint())
        sys.set_int_max_str_digits(save)
        self.assertEqual(asn1Object['content'], der_encoder(sd))
        self.assertEqual(1, sd['version'])
        self.assertEqual(1, sd['signerInfos'][0]['version'])

        algid = sd['signerInfos'][0]['signatureAlgorithm']
        self.assertEqual(rfc10082.id_MLDSA65_ECDSA_P256_SHA512, algid['algorithm'])
        self.assertFalse(algid['parameters'].hasValue())

        sig = sd['signerInfos'][0]['signature']
        self.assertEqual(3380, len(sig.asOctets()))


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
