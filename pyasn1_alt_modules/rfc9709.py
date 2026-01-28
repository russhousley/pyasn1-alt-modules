#
# This file is part of pyasn1_alt_modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2025-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1_alt_modules_license.txt
#
# Encryption Key Derivation in the CMS using HKDF with SHA-256
#
# ASN.1 source from:
# https://www.rfc_editor.org/rfc/rfc9709.txt
# Current version is based on draft-ietf-lamps-cms-cek-hkdf-sha256-01
#

from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc5751
from pyasn1_alt_modules import opentypemap

algorithmIdentifierMap = opentypemap.get('algorithmIdentifierMap')


# Import from RFC 5280

AlgorithmIdentifier = rfc5280.AlgorithmIdentifier


# Import from RFC 5751

SMIMECapability = rfc5751.SMIMECapability


# Algorithm Identifier for CEK_HKDF_SHA256

id_alg_cek_hkdf_sha256 = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 16, 3, 31))


class ContentEncryptionAlgorithmIdentifier(AlgorithmIdentifier):
    pass


cea_CEKHKDFSHA256 = ContentEncryptionAlgorithmIdentifier()
cea_CEKHKDFSHA256['algorithm'] = id_alg_cek_hkdf_sha256
cea_CEKHKDFSHA256['parameters'] = AlgorithmIdentifier()


# S/MIIME Capability for CEK_HKDF_SHA256

cap_CMSCEKHKDFSHA256 = SMIMECapability()
cap_CMSCEKHKDFSHA256['capabilityID'] = id_alg_cek_hkdf_sha256
# cap_CMSCEKHKDFSHA256['parameters'] is always absent


# Update the Algorithm Identifier map

_algorithmIdentifierMapUpdate = {
    id_alg_cek_hkdf_sha256: AlgorithmIdentifier(),
}

algorithmIdentifierMap.update(_algorithmIdentifierMapUpdate)


# Do not need to update the SMIMECapability Map because the parameters
# are always absent.
