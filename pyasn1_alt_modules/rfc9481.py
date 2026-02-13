#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2023-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Certificate Management Protocol (CMP) Algorithms
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9481.txt
#
from pyasn1_alt_modules import rfc3370
from pyasn1_alt_modules import rfc3565
from pyasn1_alt_modules import rfc4055
from pyasn1_alt_modules import rfc4210
from pyasn1_alt_modules import rfc5753
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc5480
from pyasn1_alt_modules import rfc8018
from pyasn1_alt_modules import rfc8410
from pyasn1_alt_modules import rfc8692
from pyasn1_alt_modules import rfc8702
from pyasn1_alt_modules import rfc9044


# Section 2.1:  SHA2

id_sha224 = rfc4055.id_sha224

id_sha256 = rfc4055.id_sha256

id_sha384 = rfc4055.id_sha384

id_sha512 = rfc4055.id_sha512


# Section 2.2:  SHAKE

id_shake128 = rfc8692.id_shake128

id_shake256 = rfc8692.id_shake256

mda_shake128 = rfc8692.mda_shake128

mda_shake256 = rfc8692.mda_shake256


# Section 3.1:  RSA

id_RSASSA_PSS = rfc4055.id_RSASSA_PSS

id_RSASSA_PSS_SHAKE128 = rfc8692.id_RSASSA_PSS_SHAKE128

id_RSASSA_PSS_SHAKE256 = rfc8692.id_RSASSA_PSS_SHAKE256

sha224WithRSAEncryption = rfc4055.sha224WithRSAEncryption

sha256WithRSAEncryption = rfc4055.sha256WithRSAEncryption

sha384WithRSAEncryption = rfc4055.sha384WithRSAEncryption

sha512WithRSAEncryption = rfc4055.sha512WithRSAEncryption

pk_rsaSSA_PSS_SHAKE128 = rfc8692.pk_rsaSSA_PSS_SHAKE128

pk_rsaSSA_PSS_SHAKE256 = rfc8692.pk_rsaSSA_PSS_SHAKE256

sa_rSASSA_PSS_SHAKE128 = rfc8692.sa_rSASSA_PSS_SHAKE128

sa_rSASSA_PSS_SHAKE256 = rfc8692.sa_rSASSA_PSS_SHAKE256

sa_rsassapssWithSHAKE128 = rfc8692.sa_rSASSA_PSS_SHAKE128

sa_rsassapssWithSHAKE256 = rfc8692.sa_rSASSA_PSS_SHAKE256


# Section 3.2:  ECDSA

ecdsa_with_SHA224 = rfc5480.ecdsa_with_SHA224

ecdsa_with_SHA256 = rfc5480.ecdsa_with_SHA256

ecdsa_with_SHA384 = rfc5480.ecdsa_with_SHA384

ecdsa_with_SHA512 = rfc5480.ecdsa_with_SHA512

secp192r1 = rfc5480.secp192r1
      
secp224r1 = rfc5480.secp224r1

secp256r1 = rfc5480.secp256r1

secp256r1 = rfc5480.secp256r1

secp256r1 = rfc5480.secp256r1

id_ecdsa_with_shake128 = rfc8692.id_ecdsa_with_shake128

id_ecdsa_with_shake256 = rfc8692.id_ecdsa_with_shake256

sa_ecdsa_with_shake128 = rfc8692.sa_ecdsa_with_shake128

sa_ecdsa_with_shake256 = rfc8692.sa_ecdsa_with_shake256

sa_ecdsaWithSHAKE128 = rfc8692.sa_ecdsa_with_shake128

sa_ecdsaWithSHAKE256 = rfc8692.sa_ecdsa_with_shake256


# Section 3.3:  EdDSA

id_Ed25519 = rfc8410.id_Ed25519

id_Ed448 = rfc8410.id_Ed448


# Section 4.1.1:  Diffie-Hellman

id_alg_ESDH = rfc3370.id_alg_ESDH


# Section 4.1.2:  ECDH

dhSinglePass_stdDH_sha224kdf_scheme = rfc5753.dhSinglePass_stdDH_sha224kdf_scheme

dhSinglePass_stdDH_sha256kdf_scheme = rfc5753.dhSinglePass_stdDH_sha256kdf_scheme

dhSinglePass_stdDH_sha384kdf_scheme = rfc5753.dhSinglePass_stdDH_sha384kdf_scheme

dhSinglePass_stdDH_sha512kdf_scheme = rfc5753.dhSinglePass_stdDH_sha512kdf_scheme

dhSinglePass_cofactorDH_sha224kdf_scheme = rfc5753.dhSinglePass_cofactorDH_sha224kdf_scheme

dhSinglePass_cofactorDH_sha256kdf_scheme = rfc5753.dhSinglePass_cofactorDH_sha256kdf_scheme

dhSinglePass_cofactorDH_sha256kdf_scheme = rfc5753.dhSinglePass_cofactorDH_sha256kdf_scheme

dhSinglePass_cofactorDH_sha256kdf_scheme = rfc5753.dhSinglePass_cofactorDH_sha256kdf_scheme

mqvSinglePass_sha224kdf_scheme = rfc5753.mqvSinglePass_sha224kdf_scheme

mqvSinglePass_sha256kdf_scheme = rfc5753.mqvSinglePass_sha256kdf_scheme

mqvSinglePass_sha384kdf_scheme = rfc5753.mqvSinglePass_sha384kdf_scheme

mqvSinglePass_sha512kdf_scheme = rfc5753.mqvSinglePass_sha512kdf_scheme

id_X25519 = rfc8410.id_X25519

id_X448 = rfc8410.id_X448


# Section 4.2.1:  RSA

rsaEncryption = rfc4055.rsaEncryption

id_RSAES_OAEP = rfc4055.id_RSAES_OAEP


# Section 4.3.1:  AES Key Wrap

id_aes128_wrap = rfc3565.id_aes128_wrap

id_aes192_wrap = rfc3565.id_aes192_wrap

id_aes256_wrap = rfc3565.id_aes256_wrap


# Section 4.4.1:  PBKDF2

id_PBKDF2 = rfc8018.id_PBKDF2


# Section 5.1:  AES-CBC

id_aes128_CBC = rfc3565.id_aes128_CBC

id_aes192_CBC = rfc3565.id_aes192_CBC

id_aes256_CBC = rfc3565.id_aes256_CBC


# Section 6.1.1:  PasswordBasedMac

id_PasswordBasedMac = rfc4210.id_PasswordBasedMac


# Section 6.1.2:  PBMAC1

id_PBMAC1 = rfc8018.id_PBMAC1


# Section 6.2.1:  SHA2-Based HMAC

id_hmacWithSHA224 = rfc8018.id_hmacWithSHA224

id_hmacWithSHA256 = rfc8018.id_hmacWithSHA256

id_hmacWithSHA384 = rfc8018.id_hmacWithSHA384

id_hmacWithSHA512 = rfc8018.id_hmacWithSHA512


# Section 6.2.2:  AES-GMAC

id_aes128_GMAC = rfc9044.id_aes128_GMAC

id_aes192_GMAC = rfc9044.id_aes192_GMAC

id_aes256_GMAC = rfc9044.id_aes256_GMAC


# Section 6.2.3:  SHAKE-Based KMAC

id_KMACWithSHAKE128 = rfc8702.id_KMACWithSHAKE128

id_KMACWithSHAKE256 = rfc8702.id_KMACWithSHAKE256


# Note that there is no need to update the Algorithm Identifiers Map.
# The Algorithm Identifiers Map has already been updated by importing
# the module that originally defined the object identifier.
