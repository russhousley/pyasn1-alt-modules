#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# MAC Address Other Name
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfcXXXX.txt

from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import opentypemap

otherNamesMap = opentypemap.get('otherNamesMap')
 
 
# Object Identifier Arc

id_pkix = rfc5280.id_pkix

id_on = id_pkix + (8, )


# Other Name for MAC Address

id_on_MACAddress = id_on + (12, )


class MACAddress(univ.OctetString):
    subtypeSpec=constraint.ConstraintsUnion(
        constraint.ValueSizeConstraint(6, 6),
        constraint.ValueSizeConstraint(8, 8),
        constraint.ValueSizeConstraint(12, 12),
        constraint.ValueSizeConstraint(16, 16)
    )


on_MACAddress = rfc5280.AnotherName()
on_MACAddress['type-id'] = id_on_MACAddress
on_MACAddress['value'] = MACAddress()


# Update the Other Names Map

_otherNamesMapUpdate = {
    id_on_MACAddress: MACAddress(),
}

otherNamesMap.update(_otherNamesMapUpdate)
