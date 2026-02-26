#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
# Modified by Russ Housley to incorporate Errata 8750.
#
# Copyright (c) 2025-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Related Certificates for Use in Multiple Authentications within a Protocol
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9763.txt
# https://www.rfc-editor.org/errata/eid8750
#

from pyasn1.type import char
from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc5751
from pyasn1_alt_modules import rfc6019
from pyasn1_alt_modules import opentypemap

certificateExtensionsMap = opentypemap.get('certificateExtensionsMap')

certificateAttributesMap = opentypemap.get('certificateAttributesMap')

MAX = float('inf')


# Imports from RFC 5280

id_pe = rfc5280.id_pe

Attribute = rfc5280.Attribute

AlgorithmIdentifier = rfc5280.AlgorithmIdentifier



# Imports from RFC 5652

IssuerAndSerialNumber = rfc5652.IssuerAndSerialNumber


# Imports from RFC 5751

id_aa = rfc5751.id_aa


# Imports from RFC 6019

BinaryTime = rfc6019.BinaryTime


# relatedCertificate Extension

id_pe_relatedCert = id_pe + (36, )


class DigestAlgorithmIdentifier(AlgorithmIdentifier):
    pass


class RelatedCertificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('hashAlgorithm', DigestAlgorithmIdentifier()),
        namedtype.NamedType('hashValue', univ.OctetString())
    )


# relatedCertRequest Attribute

id_aa_relatedCertRequest = id_aa + (60, )


class UniformResourceIdentifier(char.IA5String):
    pass


class RequesterCertificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('certID', IssuerAndSerialNumber()),
        namedtype.NamedType('requestTime', BinaryTime()),
        namedtype.NamedType('locationInfo', UniformResourceIdentifier()),
        namedtype.NamedType('signature', univ.BitString())
    )


# Update the Certificate Extension Map and the Certificate Attribute Map

_certificateAttributesMapUpdate = {
    id_aa_relatedCertRequest: RequesterCertificate(),
}

certificateAttributesMap.update(_certificateAttributesMapUpdate)


_certificateExtensionsMapUpdate = {
    id_pe_relatedCert: RelatedCertificate(),
}

certificateExtensionsMap.update(_certificateExtensionsMapUpdate)
