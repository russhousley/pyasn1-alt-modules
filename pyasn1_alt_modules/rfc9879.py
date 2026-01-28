#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2024-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Use of PBMAC1 in the PKCS #12 Syntax
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9879.txt
#

from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc8018


# Import from RFC 5280

AlgorithmIdentifier = rfc5280.AlgorithmIdentifier


# Import from RFC 8018

rsadsi = rfc8018.rsadsi

pkcs = rfc8018.pkcs

pkcs_5 = rfc8018.pkcs_5

id_hmacWithSHA1 = rfc8018.id_hmacWithSHA1

id_hmacWithSHA224 = rfc8018.id_hmacWithSHA224

id_hmacWithSHA256 = rfc8018.id_hmacWithSHA256

id_hmacWithSHA384 = rfc8018.id_hmacWithSHA384

id_hmacWithSHA512 = rfc8018.id_hmacWithSHA512

id_hmacWithSHA512_224 = rfc8018.id_hmacWithSHA512_224

id_hmacWithSHA512_256 = rfc8018.id_hmacWithSHA512_256

id_PBMAC1 = rfc8018.id_PBMAC1

PBMAC1_params = rfc8018.PBMAC1_params

id_PBKDF2 = rfc8018.id_PBKDF2

PBKDF2_params = rfc8018.PBKDF2_params


# HMAC algorithm identifiers

algid_hmacWithSHA1 = AlgorithmIdentifier()
algid_hmacWithSHA1['algorithm'] = id_hmacWithSHA1
algid_hmacWithSHA1['parameters'] = univ.Null("")

algid_hmacWithSHA224 = AlgorithmIdentifier()
algid_hmacWithSHA224['algorithm'] = id_hmacWithSHA224
algid_hmacWithSHA224['parameters'] = univ.Null("")

algid_hmacWithSHA256 = AlgorithmIdentifier()
algid_hmacWithSHA256['algorithm'] = id_hmacWithSHA256
algid_hmacWithSHA256['parameters'] = univ.Null("")

algid_hmacWithSHA384 = AlgorithmIdentifier()
algid_hmacWithSHA384['algorithm'] = id_hmacWithSHA384
algid_hmacWithSHA384['parameters'] = univ.Null("")

algid_hmacWithSHA512 = AlgorithmIdentifier()
algid_hmacWithSHA512['algorithm'] = id_hmacWithSHA512
algid_hmacWithSHA512['parameters'] = univ.Null("")

algid_hmacWithSHA512_224 = AlgorithmIdentifier()
algid_hmacWithSHA512_224['algorithm'] = id_hmacWithSHA512_224
algid_hmacWithSHA512_224['parameters'] = univ.Null("")

algid_hmacWithSHA512_256 = AlgorithmIdentifier()
algid_hmacWithSHA512_256['algorithm'] = id_hmacWithSHA512_256
algid_hmacWithSHA512_256['parameters'] = univ.Null("")


# No need to Update the Algorithm Identifier map or the S/MIME Capabilities map;
# these updates were handled by importing RFC 8018.
