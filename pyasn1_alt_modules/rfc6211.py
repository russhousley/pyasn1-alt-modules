#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley with assistance from asn1ate v.0.6.0.
# Modified by Russ Housley to include the opentypemap manager.
# Modified by Russ Housley for Errata 9144, which fixes the OID in this module.
#
# Copyright (c) 2019-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# CMS Algorithm Identifier Protection Attribute
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc6211.txt
# https://errata.rfc-editor.org/eid9144/
#

from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import opentypemap

cmsAttributesMap = opentypemap.get('cmsAttributesMap')


# Imports from RFC 5652

DigestAlgorithmIdentifier = rfc5652.DigestAlgorithmIdentifier

MessageAuthenticationCodeAlgorithm = rfc5652.MessageAuthenticationCodeAlgorithm

SignatureAlgorithmIdentifier = rfc5652.SignatureAlgorithmIdentifier


# CMS Algorithm Protection attribute

id_aa_cmsAlgorithmProtect = univ.ObjectIdentifier('1.2.840.113549.1.9.16.2.52')


class CMSAlgorithmProtection(univ.Sequence):
    pass

CMSAlgorithmProtection.componentType = namedtype.NamedTypes(
    namedtype.NamedType('digestAlgorithm', DigestAlgorithmIdentifier()),
    namedtype.OptionalNamedType('signatureAlgorithm',
        SignatureAlgorithmIdentifier().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
    namedtype.OptionalNamedType('macAlgorithm',
        MessageAuthenticationCodeAlgorithm().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)))
)

CMSAlgorithmProtection.subtypeSpec = constraint.ConstraintsUnion(
    constraint.WithComponentsConstraint(
        ('signatureAlgorithm', constraint.ComponentPresentConstraint()),
        ('macAlgorithm', constraint.ComponentAbsentConstraint())),
    constraint.WithComponentsConstraint(
        ('signatureAlgorithm', constraint.ComponentAbsentConstraint()),
        ('macAlgorithm', constraint.ComponentPresentConstraint()))
)


aa_cmsAlgorithmProtection = rfc5652.Attribute()
aa_cmsAlgorithmProtection['attrType'] = id_aa_cmsAlgorithmProtect
aa_cmsAlgorithmProtection['attrValues'][0] = CMSAlgorithmProtection()


# Due to a mistake in RFC 6211, provide this alternate spelling

id_aa_cmsAlgorithmProtection = id_aa_cmsAlgorithmProtect


# Update the CMS Attributes Map

_cmsAttributesMapUpdate = {
    id_aa_cmsAlgorithmProtect: CMSAlgorithmProtection(),
}

cmsAttributesMap.update(_cmsAttributesMapUpdate)
