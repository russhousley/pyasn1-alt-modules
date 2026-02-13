# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley
# Modified by Russ Housley to import items related to KDF2 and KDF3 from
#   rfc5990, which makes the algorithmIdentifierMap update more simple.
#
# Copyright (c) 2024-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Use of the SHA3 One-way Hash Functions in the CMS
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9688.txt

from pyasn1.type import univ

from pyasn1_alt_modules import rfc3279
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc5990

from pyasn1_alt_modules import opentypemap

algorithmIdentifierMap = opentypemap.get('algorithmIdentifierMap')

smimeCapabilityMap = opentypemap.get('smimeCapabilityMap')


# Imports from RFC 3279

rsaEncryption = rfc3279.rsaEncryption

RSAPublicKey = rfc3279.RSAPublicKey

ECPoint = rfc3279.ECPoint

ECDSA_Sig_Value = rfc3279.ECDSA_Sig_Value


# Imports from RFC 5280

AlgorithmIdentifier = rfc5280.AlgorithmIdentifier


# Imports from RFC 5990

x9_44 = rfc5990.x9_44

x9_44_components = rfc5990.x9_44_components

id_kdf_kdf2 = rfc5990.id_kdf_kdf2

id_kdf_kdf3 = rfc5990.id_kdf_kdf3

KDF2_HashFunction = rfc5990.KDF2_HashFunction

KDF3_HashFunction = rfc5990.KDF3_HashFunction

KeyDerivationFunction = rfc5990.KeyDerivationFunction


# OID  arcs

nistAlgorithm = univ.ObjectIdentifier('2.16.840.1.101.3.4')

hashAlgs = nistAlgorithm + (2, )

sigAlgs = nistAlgorithm + (3, )

id_alg = univ.ObjectIdentifier('1.2.840.113549.1.9.16.3')


# SHA3 Hash Algorithms

id_sha3_224 = hashAlgs + (7, )

id_sha3_256 = hashAlgs + (8, )

id_sha3_384 = hashAlgs + (9, )

id_sha3_512 = hashAlgs + (10, )

mda_sha3_224 = rfc5280.AlgorithmIdentifier()
mda_sha3_224['algorithm'] = id_sha3_224
# mda_id_sha3_224['parameters'] is absent

mda_sha3_256 = rfc5280.AlgorithmIdentifier()
mda_sha3_256['algorithm'] = id_sha3_256
# mda_id_sha3_256['parameters'] is absent

mda_sha3_384 = rfc5280.AlgorithmIdentifier()
mda_sha3_384['algorithm'] = id_sha3_384
# mda_id_sha3_384['parameters'] is absent

mda_sha3_512 = rfc5280.AlgorithmIdentifier()
mda_sha3_512['algorithm'] = id_sha3_512
# mda_id_sha3_512['parameters'] is absent

class HashAlgorithm(AlgorithmIdentifier):
    pass


# RSASSA PKCS#1 v1.5 with SHA3

id_rsassa_pkcs1_v1_5_with_sha3_224 = sigAlgs + (13, )

id_rsassa_pkcs1_v1_5_with_sha3_256 = sigAlgs + (14, )

id_rsassa_pkcs1_v1_5_with_sha3_384 = sigAlgs + (15, )

id_rsassa_pkcs1_v1_5_with_sha3_512 = sigAlgs + (16, )
      
sa_rsassa_pkcs1_v1_5_with_sha3_224 = rfc5280.AlgorithmIdentifier()
sa_rsassa_pkcs1_v1_5_with_sha3_224['algorithm'] = id_rsassa_pkcs1_v1_5_with_sha3_224
sa_rsassa_pkcs1_v1_5_with_sha3_224['parameters'] = univ.Null('')

sa_rsassa_pkcs1_v1_5_with_sha3_256 = rfc5280.AlgorithmIdentifier()
sa_rsassa_pkcs1_v1_5_with_sha3_256['algorithm'] = id_rsassa_pkcs1_v1_5_with_sha3_256
sa_rsassa_pkcs1_v1_5_with_sha3_256['parameters'] = univ.Null('')

sa_rsassa_pkcs1_v1_5_with_sha3_384 = rfc5280.AlgorithmIdentifier()
sa_rsassa_pkcs1_v1_5_with_sha3_384['algorithm'] = id_rsassa_pkcs1_v1_5_with_sha3_384
sa_rsassa_pkcs1_v1_5_with_sha3_384['parameters'] = univ.Null('')

sa_rsassa_pkcs1_v1_5_with_sha3_512 = rfc5280.AlgorithmIdentifier()
sa_rsassa_pkcs1_v1_5_with_sha3_512['algorithm'] = id_rsassa_pkcs1_v1_5_with_sha3_512
sa_rsassa_pkcs1_v1_5_with_sha3_512['parameters'] = univ.Null('')

pk_rsassa_pkcs1_v1_5_with_sha3_224 = rfc5280.SubjectPublicKeyInfo()
pk_rsassa_pkcs1_v1_5_with_sha3_224['algorithm'] = sa_rsassa_pkcs1_v1_5_with_sha3_224
# pk_rsassa_pkcs1_v1_5_with_sha3_224['subjectPublicKey'] is DER-encoded RSAPublicKey

pk_rsassa_pkcs1_v1_5_with_sha3_256 = rfc5280.SubjectPublicKeyInfo()
pk_rsassa_pkcs1_v1_5_with_sha3_256['algorithm'] = sa_rsassa_pkcs1_v1_5_with_sha3_256
# pk_rsassa_pkcs1_v1_5_with_sha3_256['subjectPublicKey'] is DER-encoded RSAPublicKey

pk_rsassa_pkcs1_v1_5_with_sha3_384 = rfc5280.SubjectPublicKeyInfo()
pk_rsassa_pkcs1_v1_5_with_sha3_384['algorithm'] = sa_rsassa_pkcs1_v1_5_with_sha3_384
# pk_rsassa_pkcs1_v1_5_with_sha3_384['subjectPublicKey'] is DER-encoded RSAPublicKey

pk_rsassa_pkcs1_v1_5_with_sha3_512 = rfc5280.SubjectPublicKeyInfo()
pk_rsassa_pkcs1_v1_5_with_sha3_512['algorithm'] = sa_rsassa_pkcs1_v1_5_with_sha3_512
# pk_rsassa_pkcs1_v1_5_with_sha3_512['subjectPublicKey'] is DER-encoded RSAPublicKey


# ECDSA with SHA3

id_ecdsa_with_sha3_224 = sigAlgs + (9, )

id_ecdsa_with_sha3_256 = sigAlgs + (10, )

id_ecdsa_with_sha3_384 = sigAlgs + (11, )

id_ecdsa_with_sha3_512 = sigAlgs + (12, )

sa_ecdsa_with_sha3_224 = rfc5280.AlgorithmIdentifier()
sa_ecdsa_with_sha3_224['algorithm'] = id_ecdsa_with_sha3_224
# sa_ecdsa_with_sha3_224['parameters'] is absent

sa_ecdsa_with_sha3_256 = rfc5280.AlgorithmIdentifier()
sa_ecdsa_with_sha3_256['algorithm'] = id_ecdsa_with_sha3_256
# sa_ecdsa_with_sha3_256['parameters'] is absent

sa_ecdsa_with_sha3_384 = rfc5280.AlgorithmIdentifier()
sa_ecdsa_with_sha3_384['algorithm'] = id_ecdsa_with_sha3_384
# sa_ecdsa_with_sha3_384['parameters'] is absent

sa_ecdsa_with_sha3_512 = rfc5280.AlgorithmIdentifier()
sa_ecdsa_with_sha3_512['algorithm'] = id_ecdsa_with_sha3_512
# sa_ecdsa_with_sha3_512['parameters'] is absent

pk_ecdsa_with_sha3_224 = rfc5280.SubjectPublicKeyInfo()
pk_ecdsa_with_sha3_224['algorithm'] = sa_ecdsa_with_sha3_224
# pk_ecdsa_with_sha3_224['subjectPublicKey'] is DER-encoded ECPoint

pk_ecdsa_with_sha3_256 = rfc5280.SubjectPublicKeyInfo()
pk_ecdsa_with_sha3_256['algorithm'] = sa_ecdsa_with_sha3_256
# pk_ecdsa_with_sha3_256['subjectPublicKey'] is DER-encoded ECPoint

pk_ecdsa_with_sha3_384 = rfc5280.SubjectPublicKeyInfo()
pk_ecdsa_with_sha3_384['algorithm'] = sa_ecdsa_with_sha3_384
# pk_ecdsa_with_sha3_384['subjectPublicKey'] is DER-encoded ECPoint

pk_ecdsa_with_sha3_512 = rfc5280.SubjectPublicKeyInfo()
pk_ecdsa_with_sha3_512['algorithm'] = sa_ecdsa_with_sha3_512
# pk_ecdsa_with_sha3_512['subjectPublicKey'] is DER-encoded ECPoint

class SignatureAlgorithm(AlgorithmIdentifier):
    pass


# HMAC with SHA3

id_hmacWithSHA3_224 = hashAlgs + (13, )

id_hmacWithSHA3_256 = hashAlgs + (14, )

id_hmacWithSHA3_384 = hashAlgs + (15, )

id_hmacWithSHA3_512 = hashAlgs + (16, )

maca_hmacWithSHA3_224 = rfc5280.AlgorithmIdentifier()
maca_hmacWithSHA3_224['algorithm'] = id_hmacWithSHA3_224
# maca_hmacWithSHA3_224['parameters'] are absent

maca_hmacWithSHA3_256 = rfc5280.AlgorithmIdentifier()
maca_hmacWithSHA3_256['algorithm'] = id_hmacWithSHA3_256
# maca_hmacWithSHA3_256['parameters'] are absent

maca_hmacWithSHA3_384 = rfc5280.AlgorithmIdentifier()
maca_hmacWithSHA3_384['algorithm'] = id_hmacWithSHA3_384
# maca_hmacWithSHA3_384['parameters'] are absent

maca_hmacWithSHA3_512 = rfc5280.AlgorithmIdentifier()
maca_hmacWithSHA3_512['algorithm'] = id_hmacWithSHA3_512
# maca_hmacWithSHA3_512['parameters'] are absent

class MACAlgorithm(AlgorithmIdentifier):
    pass


# HKDF with SHA3

id_alg_hkdf_with_sha3_224 = id_alg + (32, )

id_alg_hkdf_with_sha3_256 = id_alg + (33, )

id_alg_hkdf_with_sha3_384 = id_alg + (34, )

id_alg_hkdf_with_sha3_512 = id_alg + (35, )

kda_hkdf_with_sha3_224 = rfc5280.AlgorithmIdentifier()
kda_hkdf_with_sha3_224['algorithm'] = id_alg_hkdf_with_sha3_224
# kda_hkdf_with_sha3_224['parameters'] are absent

kda_hkdf_with_sha3_256 = rfc5280.AlgorithmIdentifier()
kda_hkdf_with_sha3_256['algorithm'] = id_alg_hkdf_with_sha3_256
# kda_hkdf_with_sha3_256['parameters'] are absent

kda_hkdf_with_sha3_384 = rfc5280.AlgorithmIdentifier()
kda_hkdf_with_sha3_384['algorithm'] = id_alg_hkdf_with_sha3_384
# kda_hkdf_with_sha3_384['parameters'] are absent

kda_hkdf_with_sha3_512 = rfc5280.AlgorithmIdentifier()
kda_hkdf_with_sha3_512['algorithm'] = id_alg_hkdf_with_sha3_512
# kda_hkdf_with_sha3_512['parameters'] are absent


# KDF using KMAC128 and KMAC512

id_kmac128 = hashAlgs + (21, )

id_kmac256 = hashAlgs + (22, )

class Customization(univ.OctetString):
    pass

kda_kmac128 = rfc5280.AlgorithmIdentifier()
kda_kmac128['algorithm'] = id_kmac128
# kda_kmac128['parameters'] are absent when Customization is ''H

kda_kmac256 = rfc5280.AlgorithmIdentifier()
kda_kmac256['algorithm'] = id_kmac256
# kda_kmac256['parameters'] are absent when Customization is ''H


# KDF2 and KDF3 with SHA3

kda_kdf2 = rfc5280.AlgorithmIdentifier()
kda_kdf2['algorithm'] = id_kdf_kdf2
kda_kdf2['parameters'] = id_sha3_256
# kda_kdf2['parameters'] can be the OID for any hash function

kda_kdf3 = rfc5280.AlgorithmIdentifier()
kda_kdf3['algorithm'] = id_kdf_kdf3
kda_kdf3['parameters'] = id_sha3_256
# kda_kdf3['parameters'] can be the OID for any hash function


# Update the algorithm identifiers map and the S/MIME capability map
#
# No need to add all of the OIDs to the algorithmIdentifierMap and the
# smimeCapabilityMap; do not add the ones where the parameters are
# always absent.  Also, the KDF OIDs do not get added to the S/MIME
# capability map.

_mapUpdate = {
    id_rsassa_pkcs1_v1_5_with_sha3_224: univ.Null(),
    id_rsassa_pkcs1_v1_5_with_sha3_256: univ.Null(),
    id_rsassa_pkcs1_v1_5_with_sha3_384: univ.Null(),
    id_rsassa_pkcs1_v1_5_with_sha3_512: univ.Null(),
    id_kmac128: Customization(),
    id_kmac256: Customization(),
}

algorithmIdentifierMap.update(_mapUpdate)

smimeCapabilityMap.update(_mapUpdate)
