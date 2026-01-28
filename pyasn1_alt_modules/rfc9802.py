# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley
#
# Copyright (c) 2025-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# HSS/LMS, XMSS, and XMSS^MT Hash-based Signature Algorithms for X.509
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc8708.txt
# https://www.rfc-editor.org/rfc/rfc9802.txt


from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc8708


# HSS/LMS Public Key and Signature Algorithm Identifier

id_alg_hss_lms_hashsig = rfc8708.id_alg_hss_lms_hashsig


class HSS_LMS_HashSig_Signature(univ.OctetString):
    pass


HSS_LMS_HashSig_PublicKey = rfc8708.HSS_LMS_HashSig_PublicKey


sa_HSS_LMS_HashSig = rfc5280.AlgorithmIdentifier()
sa_HSS_LMS_HashSig['algorithm'] = id_alg_hss_lms_hashsig
# sa_HSS_LMS_HashSig['parameters'] is alway absent


pk_HSS_LMS_HashSig = rfc5280.SubjectPublicKeyInfo()
pk_HSS_LMS_HashSig['algorithm'] = sa_HSS_LMS_HashSig
# pk_HSS_LMS_HashSig['subjectPublicKey'] CONTAINS the
#     HSS/LMS public key without any ASN.1 encoding



# XMSS Public Key and Signature Algorithm Identifier

id_alg_xmss_hashsig = univ.ObjectIdentifier('1.3.6.1.5.5.7.6.34')


class XMSS_HashSig_Signature(univ.OctetString):
    pass


class XMSS_HashSig_PublicKey(univ.OctetString):
    pass


sa_XMSS_HashSig = rfc5280.AlgorithmIdentifier()
sa_XMSS_HashSig['algorithm'] = id_alg_xmss_hashsig
# sa_XMSS_HashSig['parameters'] is alway absent


pk_XMSS_HashSig = rfc5280.SubjectPublicKeyInfo()
pk_XMSS_HashSig['algorithm'] = sa_XMSS_HashSig
# pk_XMSS_HashSig['subjectPublicKey'] CONTAINS the
#     XMSS public key without any ASN.1 encoding


# XMSS^MT Public Key and Signature Algorithm Identifier

id_alg_xmssmt_hashsig = univ.ObjectIdentifier('1.3.6.1.5.5.7.6.35')


class XMSSMT_HashSig_Signature(univ.OctetString):
    pass


class XMSSMT_HashSig_PublicKey(univ.OctetString):
    pass


sa_XMSSMT_HashSig = rfc5280.AlgorithmIdentifier()
sa_XMSSMT_HashSig['algorithm'] = id_alg_xmssmt_hashsig
# sa_XMSSMT_HashSig['parameters'] is alway absent


pk_XMSSMT_HashSig = rfc5280.SubjectPublicKeyInfo()
pk_XMSSMT_HashSig['algorithm'] = sa_XMSSMT_HashSig
# pk_XMSSMT_HashSig['subjectPublicKey'] CONTAINS the
#     XMSS^MT public key without any ASN.1 encoding
