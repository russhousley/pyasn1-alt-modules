#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Composite ML-DSA for use in X.509 Public Key Infrastructure
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc10073.txt
#

from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280


# PKIX Algorith Arc

id_alg = univ.ObjectIdentifier('1.3.6.1.5.5.7.6')


# MLDSA44 with RSA2048 PSS and SHA256

id_MLDSA44_RSA2048_PSS_SHA256 = id_alg + ( 37, )


sa_MLDSA44_RSA2048_PSS_SHA256 = rfc5280.AlgorithmIdentifier()
sa_MLDSA44_RSA2048_PSS_SHA256['algorithm'] = id_MLDSA44_RSA2048_PSS_SHA256
# sa_MLDSA44_RSA2048_PSS_SHA256['parameters'] is always absent


pk_MLDSA44_RSA2048_PSS_SHA256 = rfc5280.SubjectPublicKeyInfo()
pk_MLDSA44_RSA2048_PSS_SHA256['algorithm'] = sa_MLDSA44_RSA2048_PSS_SHA256
# pk_MLDSA44_RSA2048_PSS_SHA256['subjectPublicKey'] is the raw public key


# MLDSA44 with RSA2048 PKCS#1 v1.5 and SHA256

id_MLDSA44_RSA2048_PKCS15_SHA256 = id_alg + ( 38, )


sa_MLDSA44_RSA2048_PKCS15_SHA256 = rfc5280.AlgorithmIdentifier()
sa_MLDSA44_RSA2048_PKCS15_SHA256['algorithm'] = id_MLDSA44_RSA2048_PKCS15_SHA256
# sa_MLDSA44_RSA2048_PKCS15_SHA256['parameters'] is always absent


pk_MLDSA44_RSA2048_PKCS15_SHA256 = rfc5280.SubjectPublicKeyInfo()
pk_MLDSA44_RSA2048_PKCS15_SHA256['algorithm'] = sa_MLDSA44_RSA2048_PKCS15_SHA256
# pk_MLDSA44_RSA2048_PKCS15_SHA256['subjectPublicKey'] is the raw public key


# MLDSA44 with Ed25519 and SHA512

id_MLDSA44_Ed25519_SHA512 = id_alg + ( 39, )


sa_MLDSA44_Ed25519_SHA512 = rfc5280.AlgorithmIdentifier()
sa_MLDSA44_Ed25519_SHA512['algorithm'] = id_MLDSA44_Ed25519_SHA512
# sa_MLDSA44_Ed25519_SHA512['parameters'] is always absent


pk_MLDSA44_Ed25519_SHA512 = rfc5280.SubjectPublicKeyInfo()
pk_MLDSA44_Ed25519_SHA512['algorithm'] = sa_MLDSA44_Ed25519_SHA512
# pk_MLDSA44_Ed25519_SHA512['subjectPublicKey'] is the raw public key


# MLDSA44 with ECDSA P256 and SHA256

id_MLDSA44_ECDSA_P256_SHA256 = id_alg + ( 40, )


sa_MLDSA44_ECDSA_P256_SHA256 = rfc5280.AlgorithmIdentifier()
sa_MLDSA44_ECDSA_P256_SHA256['algorithm'] = id_MLDSA44_ECDSA_P256_SHA256
# sa_MLDSA44_ECDSA_P256_SHA256['parameters'] is always absent


pk_MLDSA44_ECDSA_P256_SHA256 = rfc5280.SubjectPublicKeyInfo()
pk_MLDSA44_ECDSA_P256_SHA256['algorithm'] = sa_MLDSA44_ECDSA_P256_SHA256
# pk_MLDSA44_ECDSA_P256_SHA256['subjectPublicKey'] is the raw public key


# MLDSA65 with RSA3072 PSS and SHA512

id_MLDSA65_RSA3072_PSS_SHA512 = id_alg + ( 41, )


sa_MLDSA65_RSA3072_PSS_SHA512 = rfc5280.AlgorithmIdentifier()
sa_MLDSA65_RSA3072_PSS_SHA512['algorithm'] = id_MLDSA65_RSA3072_PSS_SHA512
# sa_MLDSA65_RSA3072_PSS_SHA512['parameters'] is always absent


pk_MLDSA65_RSA3072_PSS_SHA512 = rfc5280.SubjectPublicKeyInfo()
pk_MLDSA65_RSA3072_PSS_SHA512['algorithm'] = sa_MLDSA65_RSA3072_PSS_SHA512
# pk_MLDSA65_RSA3072_PSS_SHA512['subjectPublicKey'] is the raw public key


# MLDSA65 with RSA3072 PKCS#1 v1.5 and SHA512

id_MLDSA65_RSA3072_PKCS15_SHA512 = id_alg + ( 42, )


sa_MLDSA65_RSA3072_PKCS15_SHA512 = rfc5280.AlgorithmIdentifier()
sa_MLDSA65_RSA3072_PKCS15_SHA512['algorithm'] = id_MLDSA65_RSA3072_PKCS15_SHA512
# sa_MLDSA65_RSA3072_PKCS15_SHA512['parameters'] is always absent


pk_MLDSA65_RSA3072_PKCS15_SHA512 = rfc5280.SubjectPublicKeyInfo()
pk_MLDSA65_RSA3072_PKCS15_SHA512['algorithm'] = sa_MLDSA65_RSA3072_PKCS15_SHA512
# pk_MLDSA65_RSA3072_PKCS15_SHA512['subjectPublicKey'] is the raw public key


# MLDSA65 with RSA4096 PSS and SHA512

id_MLDSA65_RSA4096_PSS_SHA512 = id_alg + ( 43, )


sa_MLDSA65_RSA4096_PSS_SHA512 = rfc5280.AlgorithmIdentifier()
sa_MLDSA65_RSA4096_PSS_SHA512['algorithm'] = id_MLDSA65_RSA4096_PSS_SHA512
# sa_MLDSA65_RSA4096_PSS_SHA512['parameters'] is always absent


pk_MLDSA65_RSA4096_PSS_SHA512 = rfc5280.SubjectPublicKeyInfo()
pk_MLDSA65_RSA4096_PSS_SHA512['algorithm'] = sa_MLDSA65_RSA4096_PSS_SHA512
# pk_MLDSA65_RSA4096_PSS_SHA512['subjectPublicKey'] is the raw public key


# MLDSA65 with RSA4096 PKCS#1 v1.5 and SHA512

id_MLDSA65_RSA4096_PKCS15_SHA512 = id_alg + ( 44, )


sa_MLDSA65_RSA4096_PKCS15_SHA512 = rfc5280.AlgorithmIdentifier()
sa_MLDSA65_RSA4096_PKCS15_SHA512['algorithm'] = id_MLDSA65_RSA4096_PKCS15_SHA512
# sa_MLDSA65_RSA4096_PKCS15_SHA512['parameters'] is always absent


pk_MLDSA65_RSA4096_PKCS15_SHA512 = rfc5280.SubjectPublicKeyInfo()
pk_MLDSA65_RSA4096_PKCS15_SHA512['algorithm'] = sa_MLDSA65_RSA4096_PKCS15_SHA512
# pk_MLDSA65_RSA4096_PKCS15_SHA512['subjectPublicKey'] is the raw public key


# MLDSA65 with ECDSA P256 and SHA512

id_MLDSA65_ECDSA_P256_SHA512 = id_alg + ( 45, )


sa_MLDSA65_ECDSA_P256_SHA512 = rfc5280.AlgorithmIdentifier()
sa_MLDSA65_ECDSA_P256_SHA512['algorithm'] = id_MLDSA65_ECDSA_P256_SHA512
# sa_MLDSA65_ECDSA_P256_SHA512['parameters'] is always absent


pk_MLDSA65_ECDSA_P256_SHA512 = rfc5280.SubjectPublicKeyInfo()
pk_MLDSA65_ECDSA_P256_SHA512['algorithm'] = sa_MLDSA65_ECDSA_P256_SHA512
# pk_MLDSA65_ECDSA_P256_SHA512['subjectPublicKey'] is the raw public key


# MLDSA65 with ECDSA P384 and SHA512

id_MLDSA65_ECDSA_P384_SHA512 = id_alg + ( 46, )


sa_MLDSA65_ECDSA_P384_SHA512 = rfc5280.AlgorithmIdentifier()
sa_MLDSA65_ECDSA_P384_SHA512['algorithm'] = id_MLDSA65_ECDSA_P384_SHA512
# sa_MLDSA65_ECDSA_P384_SHA512['parameters'] is always absent


pk_MLDSA65_ECDSA_P384_SHA512 = rfc5280.SubjectPublicKeyInfo()
pk_MLDSA65_ECDSA_P384_SHA512['algorithm'] = sa_MLDSA65_ECDSA_P384_SHA512
# pk_MLDSA65_ECDSA_P384_SHA512['subjectPublicKey'] is the raw public key


# MLDSA65 with ECDSA brainpoolP256r1 and SHA512

id_MLDSA65_ECDSA_brainpoolP256r1_SHA512 = id_alg + ( 47, )


sa_MLDSA65_ECDSA_brainpoolP256r1_SHA512 = rfc5280.AlgorithmIdentifier()
sa_MLDSA65_ECDSA_brainpoolP256r1_SHA512['algorithm'] = id_MLDSA65_ECDSA_brainpoolP256r1_SHA512
# sa_MLDSA65_ECDSA_brainpoolP256r1_SHA512['parameters'] is always absent


pk_MLDSA65_ECDSA_brainpoolP256r1_SHA512 = rfc5280.SubjectPublicKeyInfo()
pk_MLDSA65_ECDSA_brainpoolP256r1_SHA512['algorithm'] = sa_MLDSA65_ECDSA_brainpoolP256r1_SHA512
# pk_MLDSA65_ECDSA_brainpoolP256r1_SHA512['subjectPublicKey'] is the raw public key


# MLDSA65 with Ed25519 and SHA512

id_MLDSA65_Ed25519_SHA512 = id_alg + ( 48, )


sa_MLDSA65_Ed25519_SHA512 = rfc5280.AlgorithmIdentifier()
sa_MLDSA65_Ed25519_SHA512['algorithm'] = id_MLDSA65_Ed25519_SHA512
# sa_MLDSA65_Ed25519_SHA512['parameters'] is always absent


pk_MLDSA65_Ed25519_SHA512 = rfc5280.SubjectPublicKeyInfo()
pk_MLDSA65_Ed25519_SHA512['algorithm'] = sa_MLDSA65_Ed25519_SHA512
# pk_MLDSA65_Ed25519_SHA512['subjectPublicKey'] is the raw public key


# MLDSA87 with ECDSA P384 and SHA512

id_MLDSA87_ECDSA_P384_SHA512 = id_alg + ( 49, )


sa_MLDSA87_ECDSA_P384_SHA512 = rfc5280.AlgorithmIdentifier()
sa_MLDSA87_ECDSA_P384_SHA512['algorithm'] = id_MLDSA87_ECDSA_P384_SHA512
# sa_MLDSA87_ECDSA_P384_SHA512['parameters'] is always absent


pk_MLDSA87_ECDSA_P384_SHA512 = rfc5280.SubjectPublicKeyInfo()
pk_MLDSA87_ECDSA_P384_SHA512['algorithm'] = sa_MLDSA87_ECDSA_P384_SHA512
# pk_MLDSA87_ECDSA_P384_SHA512['subjectPublicKey'] is the raw public key


# MLDSA87 with ECDSA brainpoolP384r1 and SHA512

id_MLDSA87_ECDSA_brainpoolP384r1_SHA512 = id_alg + ( 50, )


sa_MLDSA87_ECDSA_brainpoolP384r1_SHA512 = rfc5280.AlgorithmIdentifier()
sa_MLDSA87_ECDSA_brainpoolP384r1_SHA512['algorithm'] = id_MLDSA87_ECDSA_brainpoolP384r1_SHA512
# sa_MLDSA87_ECDSA_brainpoolP384r1_SHA512['parameters'] is always absent


pk_MLDSA87_ECDSA_brainpoolP384r1_SHA512 = rfc5280.SubjectPublicKeyInfo()
pk_MLDSA87_ECDSA_brainpoolP384r1_SHA512['algorithm'] = sa_MLDSA87_ECDSA_brainpoolP384r1_SHA512
# pk_MLDSA87_ECDSA_brainpoolP384r1_SHA512['subjectPublicKey'] is the raw public key


# MLDSA87 with Ed448 and SHAKE256

id_MLDSA87_Ed448_SHAKE256 = id_alg + ( 51, )


sa_MLDSA87_Ed448_SHAKE256 = rfc5280.AlgorithmIdentifier()
sa_MLDSA87_Ed448_SHAKE256['algorithm'] = id_MLDSA87_Ed448_SHAKE256
# sa_MLDSA87_Ed448_SHAKE256['parameters'] is always absent


pk_MLDSA87_Ed448_SHAKE256 = rfc5280.SubjectPublicKeyInfo()
pk_MLDSA87_Ed448_SHAKE256['algorithm'] = sa_MLDSA87_Ed448_SHAKE256
# pk_MLDSA87_Ed448_SHAKE256['subjectPublicKey'] is the raw public key


# MLDSA87 with RSA3072 PSS and SHA512

id_MLDSA87_RSA3072_PSS_SHA512 = id_alg + ( 52, )


sa_MLDSA87_RSA3072_PSS_SHA512 = rfc5280.AlgorithmIdentifier()
sa_MLDSA87_RSA3072_PSS_SHA512['algorithm'] = id_MLDSA87_RSA3072_PSS_SHA512
# sa_MLDSA87_RSA3072_PSS_SHA512['parameters'] is always absent


pk_MLDSA87_RSA3072_PSS_SHA512 = rfc5280.SubjectPublicKeyInfo()
pk_MLDSA87_RSA3072_PSS_SHA512['algorithm'] = sa_MLDSA87_RSA3072_PSS_SHA512
# pk_MLDSA87_RSA3072_PSS_SHA512['subjectPublicKey'] is the raw public key


# MLDSA87 with RSA4096 PSS and SHA512

id_MLDSA87_RSA4096_PSS_SHA512 = id_alg + ( 53, )


sa_MLDSA87_RSA4096_PSS_SHA512 = rfc5280.AlgorithmIdentifier()
sa_MLDSA87_RSA4096_PSS_SHA512['algorithm'] = id_MLDSA87_RSA4096_PSS_SHA512
# sa_MLDSA87_RSA4096_PSS_SHA512['parameters'] is always absent


pk_MLDSA87_RSA4096_PSS_SHA512 = rfc5280.SubjectPublicKeyInfo()
pk_MLDSA87_RSA4096_PSS_SHA512['algorithm'] = sa_MLDSA87_RSA4096_PSS_SHA512
# pk_MLDSA87_RSA4096_PSS_SHA512['subjectPublicKey'] is the raw public key


# MLDSA87 with ECDSA P521 and SHA512

id_MLDSA87_ECDSA_P521_SHA512 = id_alg + ( 54, )


sa_MLDSA87_ECDSA_P521_SHA512 = rfc5280.AlgorithmIdentifier()
sa_MLDSA87_ECDSA_P521_SHA512['algorithm'] = id_MLDSA87_ECDSA_P521_SHA512
# sa_MLDSA87_ECDSA_P521_SHA512['parameters'] is always absent


pk_MLDSA87_ECDSA_P521_SHA512 = rfc5280.SubjectPublicKeyInfo()
pk_MLDSA87_ECDSA_P521_SHA512['algorithm'] = sa_MLDSA87_ECDSA_P521_SHA512
# pk_MLDSA87_ECDSA_P521_SHA512['subjectPublicKey'] is the raw public key


# No need to update the Algorithm Identifiers Map or the SMIMECapability Map
# because the parameters item in the AlgorithmIdentifier is always absent
