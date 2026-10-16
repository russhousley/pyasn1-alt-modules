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
from pyasn1_alt_modules import rfc5958
from pyasn1_alt_modules import rfc10073


class CompositeSignatureAlgorithmOIDsTestCase(unittest.TestCase):

    def testCompositSigObjectIdentifiers(self):
        oid_num_list = (
			(rfc10073.id_MLDSA44_RSA2048_PSS_SHA256, 37),
			(rfc10073.id_MLDSA44_RSA2048_PKCS15_SHA256, 38),
			(rfc10073.id_MLDSA44_Ed25519_SHA512, 39),
			(rfc10073.id_MLDSA44_ECDSA_P256_SHA256, 40),
			(rfc10073.id_MLDSA65_RSA3072_PSS_SHA512, 41),
			(rfc10073.id_MLDSA65_RSA3072_PKCS15_SHA512, 42),
			(rfc10073.id_MLDSA65_RSA4096_PSS_SHA512, 43),
			(rfc10073.id_MLDSA65_RSA4096_PKCS15_SHA512, 44),
			(rfc10073.id_MLDSA65_ECDSA_P256_SHA512, 45),
			(rfc10073.id_MLDSA65_ECDSA_P384_SHA512, 46),
			(rfc10073.id_MLDSA65_ECDSA_brainpoolP256r1_SHA512, 47),
			(rfc10073.id_MLDSA65_Ed25519_SHA512, 48),
			(rfc10073.id_MLDSA87_ECDSA_P384_SHA512, 49),
			(rfc10073.id_MLDSA87_ECDSA_brainpoolP384r1_SHA512, 50),
			(rfc10073.id_MLDSA87_Ed448_SHAKE256, 51),
			(rfc10073.id_MLDSA87_RSA3072_PSS_SHA512, 52),
			(rfc10073.id_MLDSA87_RSA4096_PSS_SHA512, 53),
			(rfc10073.id_MLDSA87_ECDSA_P521_SHA512, 54)
		)

        for (oid, num) in oid_num_list:
            self.assertTrue(oid.prettyPrint().endswith(str(num)))


class MLDSAECDSAP256SHA256CertTestCase(unittest.TestCase):
    pem_text = """\
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
M91euICuPFed6iRs6CctTCInbK8=
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Certificate()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        save = sys.get_int_max_str_digits()
        sys.set_int_max_str_digits(0)
        self.assertTrue(asn1Object.prettyPrint())
        sys.set_int_max_str_digits(save)
        self.assertEqual(substrate, der_encoder(asn1Object))

        algid_list = (
            asn1Object['tbsCertificate']['signature'],
            asn1Object['tbsCertificate']['subjectPublicKeyInfo']['algorithm'],
            asn1Object['signatureAlgorithm'])
        for algid in algid_list:
            self.assertEqual(rfc10073.id_MLDSA44_ECDSA_P256_SHA256, algid['algorithm'])
            self.assertFalse(algid['parameters'].hasValue())

        spki = asn1Object['tbsCertificate']['subjectPublicKeyInfo']
        self.assertEqual(1377, len(spki['subjectPublicKey'].asOctets()))


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
