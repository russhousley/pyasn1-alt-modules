# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley
#
# Copyright (c) 2025-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# SLH-DSA Signature Algorithm for the CMS
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9814.txt
#

from pyasn1.type import constraint
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280


# Object Identifiers

nistAlgorithms = univ.ObjectIdentifier('2.16.840.1.101.3.4')

sigAlgs = nistAlgorithms + (3, )

id_slh_dsa_sha2_128s = sigAlgs + (20, )

id_slh_dsa_sha2_128f = sigAlgs + (21, )

id_slh_dsa_sha2_192s = sigAlgs + (22, )

id_slh_dsa_sha2_192f = sigAlgs + (23, )

id_slh_dsa_sha2_256s = sigAlgs + (24, )

id_slh_dsa_sha2_256f = sigAlgs + (25, )

id_slh_dsa_shake_128s = sigAlgs + (26, )

id_slh_dsa_shake_128f = sigAlgs + (27, )

id_slh_dsa_shake_192s = sigAlgs + (28, )

id_slh_dsa_shake_192f = sigAlgs + (29, )

id_slh_dsa_shake_256s = sigAlgs + (30, )

id_slh_dsa_shake_256f = sigAlgs + (31, )


# Signature Algorithm Identifier

sa_slh_dsa_sha2_128s = rfc5280.AlgorithmIdentifier()
sa_slh_dsa_sha2_128s['algorithm'] = id_slh_dsa_sha2_128s
# sa_slh_dsa_sha2_128s['parameters'] is always absent

sa_slh_dsa_sha2_128f = rfc5280.AlgorithmIdentifier()
sa_slh_dsa_sha2_128f['algorithm'] = id_slh_dsa_sha2_128f
# sa_slh_dsa_sha2_128f['parameters'] is always absent

sa_slh_dsa_sha2_192s = rfc5280.AlgorithmIdentifier()
sa_slh_dsa_sha2_192s['algorithm'] = id_slh_dsa_sha2_192s
# sa_slh_dsa_sha2_192s['parameters'] is always absent

sa_slh_dsa_sha2_192f = rfc5280.AlgorithmIdentifier()
sa_slh_dsa_sha2_192f['algorithm'] = id_slh_dsa_sha2_192f
# sa_slh_dsa_sha2_192f['parameters'] is always absent

sa_slh_dsa_sha2_256s = rfc5280.AlgorithmIdentifier()
sa_slh_dsa_sha2_256s['algorithm'] = id_slh_dsa_sha2_256s
# sa_slh_dsa_sha2_256s['parameters'] is always absent

sa_slh_dsa_sha2_256f = rfc5280.AlgorithmIdentifier()
sa_slh_dsa_sha2_256f['algorithm'] = id_slh_dsa_sha2_256f
# sa_slh_dsa_sha2_256f['parameters'] is always absent

sa_slh_dsa_shake_128s = rfc5280.AlgorithmIdentifier()
sa_slh_dsa_shake_128s['algorithm'] = id_slh_dsa_shake_128s
# sa_slh_dsa_shake_128s['parameters'] is always absent

sa_slh_dsa_shake_128f = rfc5280.AlgorithmIdentifier()
sa_slh_dsa_shake_128f['algorithm'] = id_slh_dsa_shake_128f
# sa_slh_dsa_shake_128f['parameters'] is always absent

sa_slh_dsa_shake_192s = rfc5280.AlgorithmIdentifier()
sa_slh_dsa_shake_192s['algorithm'] = id_slh_dsa_shake_192s
# sa_slh_dsa_shake_192s['parameters'] is always absent

sa_slh_dsa_shake_192f = rfc5280.AlgorithmIdentifier()
sa_slh_dsa_shake_192f['algorithm'] = id_slh_dsa_shake_192f
# sa_slh_dsa_shake_192f['parameters'] is always absent

sa_slh_dsa_shake_256s = rfc5280.AlgorithmIdentifier()
sa_slh_dsa_shake_256s['algorithm'] = id_slh_dsa_shake_256s
# sa_slh_dsa_shake_256s['parameters'] is always absent

sa_slh_dsa_shake_256f = rfc5280.AlgorithmIdentifier()
sa_slh_dsa_shake_256f['algorithm'] = id_slh_dsa_shake_256f
# sa_slh_dsa_shake_256f['parameters'] is always absent


# Public Keys

pk_slh_dsa_sha2_128s = rfc5280.SubjectPublicKeyInfo()
pk_slh_dsa_sha2_128s['algorithm'] = sa_slh_dsa_sha2_128s
# pk_slh_dsa_sha2_128s['subjectPublicKey'] is the raw public key

pk_slh_dsa_sha2_128f = rfc5280.SubjectPublicKeyInfo()
pk_slh_dsa_sha2_128f['algorithm'] = sa_slh_dsa_sha2_128f
# pk_slh_dsa_sha2_128f['subjectPublicKey'] is the raw public key

pk_slh_dsa_sha2_192s = rfc5280.SubjectPublicKeyInfo()
pk_slh_dsa_sha2_192s['algorithm'] = sa_slh_dsa_sha2_192s
# pk_slh_dsa_sha2_192s['subjectPublicKey'] is the raw public key

pk_slh_dsa_sha2_192f = rfc5280.SubjectPublicKeyInfo()
pk_slh_dsa_sha2_192f['algorithm'] = sa_slh_dsa_sha2_192f
# pk_slh_dsa_sha2_192f['subjectPublicKey'] is the raw public key

pk_slh_dsa_sha2_256s = rfc5280.SubjectPublicKeyInfo()
pk_slh_dsa_sha2_256s['algorithm'] = sa_slh_dsa_sha2_256s
# pk_slh_dsa_sha2_256s['subjectPublicKey'] is the raw public key

pk_slh_dsa_sha2_256f = rfc5280.SubjectPublicKeyInfo()
pk_slh_dsa_sha2_256f['algorithm'] = sa_slh_dsa_sha2_256f
# pk_slh_dsa_sha2_256f['subjectPublicKey'] is the raw public key

pk_slh_dsa_shake_128s = rfc5280.SubjectPublicKeyInfo()
pk_slh_dsa_shake_128s['algorithm'] = sa_slh_dsa_shake_128s
# pk_slh_dsa_shake_128s['subjectPublicKey'] is the raw public key

pk_slh_dsa_shake_128f = rfc5280.SubjectPublicKeyInfo()
pk_slh_dsa_shake_128f['algorithm'] = sa_slh_dsa_shake_128f
# pk_slh_dsa_shake_128f['subjectPublicKey'] is the raw public key

pk_slh_dsa_shake_192s = rfc5280.SubjectPublicKeyInfo()
pk_slh_dsa_shake_192s['algorithm'] = sa_slh_dsa_shake_192s
# pk_slh_dsa_shake_192s['subjectPublicKey'] is the raw public key

pk_slh_dsa_shake_192f = rfc5280.SubjectPublicKeyInfo()
pk_slh_dsa_shake_192f['algorithm'] = sa_slh_dsa_shake_192f
# pk_slh_dsa_shake_192f['subjectPublicKey'] is the raw public key

pk_slh_dsa_shake_256s = rfc5280.SubjectPublicKeyInfo()
pk_slh_dsa_shake_256s['algorithm'] = sa_slh_dsa_shake_256s
# pk_slh_dsa_shake_256s['subjectPublicKey'] is the raw public key

pk_slh_dsa_shake_256f = rfc5280.SubjectPublicKeyInfo()
pk_slh_dsa_shake_256f['algorithm'] = sa_slh_dsa_shake_256f
# pk_slh_dsa_shake_256f['subjectPublicKey'] is the raw public key


# Private key outside an asymmetric key package

class SLH_DSA_PrivateKey(univ.OctetString):
    subtypeSpec = constraint.ConstraintsUnion(
        constraint.ValueSizeConstraint(64, 64),
        constraint.ValueSizeConstraint(96, 96),
        constraint.ValueSizeConstraint(128, 128) )


# Public key outside of a certificate

class SLH_DSA_PublicKey(univ.OctetString):
    subtypeSpec = constraint.ConstraintsUnion(
        constraint.ValueSizeConstraint(32, 32),
        constraint.ValueSizeConstraint(48, 48),
        constraint.ValueSizeConstraint(64, 64) )


# No need to add the id_alg_slh_dsa_* object identifiers to the
# algorithmIdentifierMap or the smimeCapabilityMap because the
# parameters are always absent.
