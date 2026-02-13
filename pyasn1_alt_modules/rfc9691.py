#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley with some assistance from asn1ate v.0.6.0.
#
# Copyright (c) 2024-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# RPKI Signed Trust Anchor List
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9691.txt
#

from pyasn1.type import char
from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import opentypemap

cmsContentTypesMap = opentypemap.get('cmsContentTypesMap')

MAX = float('inf')


# Import from RFC 5280

SubjectPublicKeyInfo = rfc5280.SubjectPublicKeyInfo


# Signed Trust Anchor List
 
class CertificateURI(char.IA5String):
    pass


class TAKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('comments', univ.SequenceOf(
            componentType=char.UTF8String()).subtype(
                subtypeSpec=constraint.ValueSizeConstraint(0, MAX))),
        namedtype.NamedType('certificateURIs', univ.SequenceOf(
            componentType=CertificateURI()).subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType('subjectPublicKeyInfo', SubjectPublicKeyInfo())
    )


class TAK(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('version',
            univ.Integer().subtype(value=0)),
        namedtype.NamedType('current', TAKey()),
        namedtype.OptionalNamedType('predecessor',
            TAKey().subtype(explicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.OptionalNamedType('successor',
            TAKey().subtype(explicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatConstructed, 1)))
)


id_ct_signedTAL = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 16, 1, 50))


# Update the CMS Content Type Map

_cmsContentTypesMapUpdate = {
    id_ct_signedTAL: TAK(),
}

cmsContentTypesMap.update(_cmsContentTypesMapUpdate)
