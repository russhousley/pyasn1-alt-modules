# coding: utf-8
#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley with some assistance from asn1ate v.0.6.0.
#
# Copyright (c) 2025-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Alternative Certificate Formats for the PKIX Certificate Management Protocols
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc4212.txt
# https://www.rfc-editor.org/errata/eid8447
# https://www.rfc-editor.org/errata/eid8448
#

from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ
from pyasn1.type import useful

from pyasn1_alt_modules import rfc4211
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc5755
from pyasn1_alt_modules import opentypemap

cmsAttributesMap = opentypemap.get('cmsAttributesMap')


# Imports from RFC 4211

id_pkix = rfc4211.id_pkix

id_pkip = rfc4211.id_pkip

id_regCtrl = rfc4211.id_regCtrl

AttributeTypeAndValue = rfc4211.AttributeTypeAndValue

Controls = rfc4211.Controls


# Imports from RFC 5280

AlgorithmIdentifier = rfc5280.AlgorithmIdentifier

Attribute = rfc5280.Attribute

CertificateSerialNumber = rfc5280.CertificateSerialNumber

Extensions = rfc5280.Extensions

UniqueIdentifier = rfc5280.UniqueIdentifier


# Imports from RFC 5755

AttCertVersion = rfc5755.AttCertVersion

Holder = rfc5755.Holder

AttCertIssuer = rfc5755.AttCertIssuer


# Alternate Certificate Template

class AltCertTemplate(AttributeTypeAndValue):
    pass


id_regCtrl_altCertTemplate = id_regCtrl + (7, )


# X.509 Attribute Certificate CertTemplate

class OptionalAttCertValidity(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('notBeforeTime',
            useful.GeneralizedTime().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType('notAfterTime',
            useful.GeneralizedTime().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 1)))
    )
    subtypeSpec = constraint.ConstraintsUnion(
        constraint.WithComponentsConstraint(
            ('notBeforeTime', constraint.ComponentPresentConstraint())),
        constraint.WithComponentsConstraint(
            ('notAfterTime', constraint.ComponentPresentConstraint()))
    )


class AttCertTemplate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('version',
            AttCertVersion().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType('holder',
            Holder().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatConstructed, 1))),
        namedtype.OptionalNamedType('issuer',
            AttCertIssuer().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatConstructed, 2))),
        namedtype.OptionalNamedType('signature',
            AlgorithmIdentifier().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 3))),
        namedtype.OptionalNamedType('serialNumber',
            CertificateSerialNumber().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 4))),
        namedtype.OptionalNamedType('attrCertValidityPeriod',
            OptionalAttCertValidity().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatConstructed, 5))),
        namedtype.OptionalNamedType('attributes',
            univ.SequenceOf(componentType=Attribute()).subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))),
        namedtype.OptionalNamedType('issuerUniqueID',
            UniqueIdentifier().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 7))),
        namedtype.OptionalNamedType('extensions',
            Extensions().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 8)))
    )


id_acTemplate = id_regCtrl_altCertTemplate + (1, )


# 2.2.  OpenPGP Certificate CertTemplate

class OpenPGPCertTemplate(univ.OctetString):
   pass


class OpenPGPCertTemplateExtended(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('nativeTemplate', OpenPGPCertTemplate()),
        namedtype.OptionalNamedType('controls', Controls())
    )


id_openPGPCertTemplateExt = id_regCtrl_altCertTemplate + (2, )


# Update the CMS Attribute Map

_cmsAttributesMapUpdate = {
    id_regCtrl_altCertTemplate: AltCertTemplate(),
    id_acTemplate: AttCertTemplate(),
    id_openPGPCertTemplateExt: OpenPGPCertTemplateExtended(),
}

cmsAttributesMap.update(_cmsAttributesMapUpdate)
