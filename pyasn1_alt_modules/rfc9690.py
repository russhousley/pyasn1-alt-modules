#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2025-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# KEM-RSA Algorithm with CMS KEMRecipientInfo
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9690.txt
#

from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc4055
from pyasn1_alt_modules import rfc5990


# Alias for Object Identifier

class OID(univ.ObjectIdentifier):
    pass


# Imports from RFC 5280

AlgorithmIdentifier = rfc5280.AlgorithmIdentifier

SubjectPublicKeyInfo = rfc5280.SubjectPublicKeyInfo


# Imports from RFC 4055

RSAPublicKey = rfc4055.RSAPublicKey


# Imports from RFC 5990

NullParms = rfc5990.NullParms

is18033_2 = rfc5990.is18033_2

nistAlgorithm = rfc5990.nistAlgorithm

pkcs_1 = rfc5990.pkcs_1

x9_44 = rfc5990.x9_44

x9_44_components = rfc5990.x9_44_components

Camellia_KeyWrappingScheme = rfc5990.Camellia_KeyWrappingScheme

DataEncapsulationMechanism = rfc5990.DataEncapsulationMechanism

KDF2_HashFunction = rfc5990.KDF2_HashFunction

KDF3_HashFunction = rfc5990.KDF3_HashFunction

KeyDerivationFunction = rfc5990.KeyDerivationFunction

KeyEncapsulationMechanism = rfc5990.KeyEncapsulationMechanism

X9_SymmetricKeyWrappingScheme = rfc5990.X9_SymmetricKeyWrappingScheme

id_rsa_kem = rfc5990.id_rsa_kem

id_rsa_kem_spki = rfc5990.id_rsa_kem

GenericHybridParameters = rfc5990.GenericHybridParameters

id_kem_rsa = rfc5990.id_kem_rsa

KeyLength = rfc5990.KeyLength

RsaKemParameters = rfc5990.RsaKemParameters

id_kdf_kdf2 = rfc5990.id_kdf_kdf2

id_kdf_kdf3 = rfc5990.id_kdf_kdf3

id_sha1 = rfc5990.id_sha1

id_sha224 = rfc5990.id_sha224

id_sha256 = rfc5990.id_sha256

id_sha384 = rfc5990.id_sha384

id_sha512 = rfc5990.id_sha512

id_aes128_wrap = rfc5990.id_aes128_Wrap

id_aes192_wrap = rfc5990.id_aes192_Wrap

id_aes256_wrap = rfc5990.id_aes256_Wrap

id_alg_CMS3DESwrap = rfc5990.id_alg_CMS3DESwrap

id_camellia128_wrap = rfc5990.id_camellia128_Wrap
   
id_camellia192_wrap = rfc5990.id_camellia192_Wrap

id_camellia256_wrap = rfc5990.id_camellia256_Wrap


# KEM-RSA Key Encapsulation Mechanism Algorithms

kema_rsa_kem = AlgorithmIdentifier()
kema_rsa_kem['algorithm'] = id_rsa_kem_spki
kema_rsa_kem['parameters'] = GenericHybridParameters()

kema_kem_rsa = AlgorithmIdentifier()
kema_kem_rsa['algorithm'] = id_kem_rsa
kema_kem_rsa['parameters'] = RsaKemParameters()


# RSA Public Key for use only with the KEM-RSA Algorithm 

pk_rsa_kem = SubjectPublicKeyInfo()
pk_rsa_kem['algorithm']['algorithm'] = id_rsa_kem_spki
# To limit the KDF or KWA choices, provide parameters:
# pk_rsa_kem['algorithm']['parameters'] = GenericHybridParameters()
# To provide the public key value:
# pubkey = RSAPublicKey()
# pubkey['modulus'] = n
# pubkey['publicExponent'] = e
# encodedpk = der.encoder.encode(pubkey)
# pk_rsa_kem['subjectPublicKey'] = univ.BitString.fromOctetString(encodedpk)


# Key Derivation Functions

kda_kdf2 = AlgorithmIdentifier()
kda_kdf2['algorithm'] = id_kdf_kdf2
kda_kdf2['parameters'] = KDF2_HashFunction()

kda_kdf3 = AlgorithmIdentifier()
kda_kdf3['algorithm'] = id_kdf_kdf3
kda_kdf3['parameters'] = KDF3_HashFunction()


# Hash Functions

mda_sha1 = AlgorithmIdentifier()
mda_sha1['algorithm'] = id_sha1
mda_sha1['parameters'] = NullParms("")

mda_sha224 = AlgorithmIdentifier()
mda_sha224['algorithm'] = id_sha224
mda_sha224['parameters'] = NullParms("")

mda_sha256 = AlgorithmIdentifier()
mda_sha256['algorithm'] = id_sha256
mda_sha256['parameters'] = NullParms("")

mda_sha384 = AlgorithmIdentifier()
mda_sha384['algorithm'] = id_sha384
mda_sha384['parameters'] = NullParms("")

mda_sha512 = AlgorithmIdentifier()
mda_sha512['algorithm'] = id_sha512
mda_sha512['parameters'] = NullParms("")


# Key Wrap Algorithms

kwa_aes128_wrap = AlgorithmIdentifier()
kwa_aes128_wrap['algorithm'] = id_aes128_wrap
# kwa_aes128_wrap['parameters'] are absent

kwa_aes192_wrap = AlgorithmIdentifier()
kwa_aes192_wrap['algorithm'] = id_aes192_wrap
# kwa_aes192_wrap['parameters'] are absent

kwa_aes256_wrap = AlgorithmIdentifier()
kwa_aes256_wrap['algorithm'] = id_aes256_wrap
# kwa_aes256_wrap['parameters'] are absent

kwa_3DESWrap = AlgorithmIdentifier()
kwa_3DESWrap['algorithm'] = id_alg_CMS3DESwrap
kwa_3DESWrap['parameters'] = NullParms("")

kwa_camellia128_wrap = AlgorithmIdentifier()
kwa_camellia128_wrap['algorithm'] = id_camellia128_wrap
# kwa_camellia128_wrap['parameters'] are absent
   
kwa_camellia192_wrap = AlgorithmIdentifier()
kwa_camellia192_wrap['algorithm'] = id_camellia192_wrap
# kwa_camellia192_wrap['parameters'] are absent

kwa_camellia256_wrap = AlgorithmIdentifier()
kwa_camellia256_wrap['algorithm'] = id_camellia256_wrap
# kwa_camellia256_wrap['parameters'] are absent


# No need to update the Algorithm Identifier map or the
# S/MIME Capabilities map.  Import of rfc5900 already did so.
