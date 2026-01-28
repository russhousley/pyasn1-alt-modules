# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley
#
# Copyright (c) 2024-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# HSS/LMS Hash-based Signature Algorithm for CMS
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfcXXXX.txt

from pyasn1_alt_modules import rfc8708


# Object Identifiers

id_alg_hss_lms_hashsig = rfc8708.id_alg_hss_lms_hashsig

id_alg_mts_hashsig = id_alg_hss_lms_hashsig


# Signature Algorithm Identifier

sa_HSS_LMS_HashSig = rfc8708.sa_HSS_LMS_HashSig
# sa_HSS_LMS_HashSig['parameters'] is alway absent


# Public Key

HSS_LMS_HashSig_PublicKey = rfc8708.HSS_LMS_HashSig_PublicKey

pk_HSS_LMS_HashSig = rfc8708.pk_HSS_LMS_HashSig
# pk_HSS_LMS_HashSig['subjectPublicKey'] CONTAINS the
#     HSS/LMS public key without any ASN.1 encoding
