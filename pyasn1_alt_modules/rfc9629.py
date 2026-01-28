#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley with some help from by asn1ate v.0.6.0.
#
# Copyright (c) 2023-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# CMS KEMRecipientInfo
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9629.txt
#

from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import opentypemap

otherRecipientInfoMap = opentypemap.get('otherRecipientInfoMap')

MAX = float('inf')


# Imports from RFC 5280

AlgorithmIdentifier = rfc5280.AlgorithmIdentifier


# Imports from RFC 5652

CMSVersion = rfc5652.CMSVersion

EncryptedKey = rfc5652.EncryptedKey

KeyDerivationAlgorithmIdentifier = rfc5652.KeyDerivationAlgorithmIdentifier

KeyEncryptionAlgorithmIdentifier = rfc5652.KeyEncryptionAlgorithmIdentifier

RecipientIdentifier = rfc5652.RecipientIdentifier

UserKeyingMaterial = rfc5652.UserKeyingMaterial


# Object Identifiers

id_ori = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 16, 13))

id_ori_kem = id_ori + (3,)


# KEMRecipientInfo

class KEMAlgorithmIdentifier(AlgorithmIdentifier):
    pass


class KEMRecipientInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', CMSVersion()),
        namedtype.NamedType('rid', RecipientIdentifier()),
        namedtype.NamedType('kem', KEMAlgorithmIdentifier()),
        namedtype.NamedType('kemct', univ.OctetString()),
        namedtype.NamedType('kdf', KeyDerivationAlgorithmIdentifier()),
        namedtype.NamedType('kekLength',
            univ.Integer().subtype(
                subtypeSpec=constraint.ValueRangeConstraint(1, MAX))),
        namedtype.OptionalNamedType('ukm',
            UserKeyingMaterial().subtype(explicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('wrap', KeyEncryptionAlgorithmIdentifier()),
        namedtype.NamedType('encryptedKey', EncryptedKey())
    )


# CMSORIforKEMOtherInfo

class CMSORIforKEMOtherInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('wrap', KeyEncryptionAlgorithmIdentifier()),
        namedtype.NamedType('kekLength',
            univ.Integer().subtype(
                subtypeSpec=constraint.ValueRangeConstraint(1, MAX))),
        namedtype.OptionalNamedType('ukm',
            UserKeyingMaterial().subtype(explicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 0)))
    )


# Update the CMS Other Recipient Info Map

_otherRecipientInfoMapUpdate = {
    id_ori_kem: KEMRecipientInfo(),
}

otherRecipientInfoMap.update(_otherRecipientInfoMapUpdate)
