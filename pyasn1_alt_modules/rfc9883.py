#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2025-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# An Attribute for Statement of Possession of a Private Key
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9883.txt
#

from pyasn1.type import namedtype
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc5652

from pyasn1_alt_modules import opentypemap

certificateAttributesMap = opentypemap.get('certificateAttributesMap')


# Object Identifier

id_statementOfPossession = univ.ObjectIdentifier('1.3.6.1.4.1.22112.2.1')


# privateKeyPossessionStatement Attribute

class PrivateKeyPossessionStatement(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('signer', rfc5652.IssuerAndSerialNumber()),
        namedtype.OptionalNamedType('cert', rfc5280.Certificate())
    )


# Update the Certificate Attribute Map

_certificateAttributesMapUpdate = {
    id_statementOfPossession: PrivateKeyPossessionStatement(),
}

certificateAttributesMap.update(_certificateAttributesMapUpdate)
