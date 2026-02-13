#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2025-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Clarification of RFC7030 CSR Attributes definition
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9908.txt
#

from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import namedval
from pyasn1.type import opentype
from pyasn1.type import tag
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import opentypemap

certificateAttributesMap = opentypemap.get('certificateAttributesMap')

MAX = float('inf')


# Imports from RFC 5280

Attribute = rfc5280.Attribute

AttributeType = rfc5280.AttributeType

AttributeValue = rfc5280.AttributeValue

AlgorithmIdentifier = rfc5280.AlgorithmIdentifier


# NameTemplate
# like Name, but with OPTIONAL RDN values

class SingleAttributeTemplate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', AttributeType()),
        namedtype.OptionalNamedType('value', AttributeValue(),
            openType=opentype.OpenType('type', certificateAttributesMap)
        )
    )


class RelativeDistinguishedNameTemplate(univ.SetOf):
    componentType = SingleAttributeTemplate()
    sizeSpec = constraint.ValueSizeConstraint(1, MAX)


class RDNSequenceTemplate(univ.SequenceOf):
    componentType = RelativeDistinguishedNameTemplate()


class NameTemplate(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('rdnSequence', RDNSequenceTemplate())
    )


# SubjectPublicKeyInfoTemplate
# like SubjectPublicKeyInfo, but with OPTIONAL subjectPublicKey

class SubjectPublicKeyInfoTemplate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', AlgorithmIdentifier()),
        namedtype.OptionalNamedType('subjectPublicKey', univ.BitString())
    )


# ExtensionTemplate
# like Extension, but with OPTIONAL extnValue

class ExtensionTemplate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('extnID', univ.ObjectIdentifier()),
        namedtype.DefaultedNamedType('critical', univ.Boolean().subtype(value=0)),
        namedtype.OptionalNamedType('extnValue', univ.OctetString())
    )


class ExtensionTemplates(univ.SequenceOf):
    componentType = ExtensionTemplate()
    sizeSpec = constraint.ValueSizeConstraint(1, MAX)


# Certification Request Info Template Attribute
# like CertificationRequestInfo, with OPTIONAL subject and subjectPKInfo 

id_aa = univ.ObjectIdentifier('1.2.840.113549.1.9.16.2')

id_aa_certificationRequestInfoTemplate = id_aa + (61, )


class Attributes(univ.SetOf):
    componentType = Attribute()
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


class CertificationRequestInfoTemplate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version',
            univ.Integer(namedValues=namedval.NamedValues(('v1', 0)))),
        namedtype.OptionalNamedType('subject', NameTemplate()),
        namedtype.OptionalNamedType('subjectPKInfo',
            SubjectPublicKeyInfoTemplate().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('attributes',
            Attributes().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 1)))
    )


aa_certificationRequestInfoTemplate = Attribute()
aa_certificationRequestInfoTemplate['type'] = id_aa_certificationRequestInfoTemplate
aa_certificationRequestInfoTemplate['values'][0] = CertificationRequestInfoTemplate()


# Extension Request Template Attribute
# like extensionRequest, but with OPTIONAL extnValues in each Extension

id_aa_extensionReqTemplate = id_aa + (62, )


class ExtensionReqTemplate(ExtensionTemplates):
    pass


aa_extensionReqTemplate = Attribute()
aa_extensionReqTemplate['type'] = id_aa_extensionReqTemplate
aa_extensionReqTemplate['values'][0] = ExtensionReqTemplate()


# Update the Certificate Attributes Map

_certificateMapUpdate = {
    id_aa_certificationRequestInfoTemplate: CertificationRequestInfoTemplate(),
    id_aa_extensionReqTemplate: ExtensionReqTemplate(),
}

certificateAttributesMap.update(_certificateMapUpdate)
