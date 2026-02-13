#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2024-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# The noRevAvail Certificate Extension
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9608.txt
#

from pyasn1.type import univ
from pyasn1_alt_modules import opentypemap


certificateExtensionsMap = opentypemap.get('certificateExtensionsMap')


# Object Identifiers

id_ce = univ.ObjectIdentifier((2, 5, 29, ))

id_ce_noRevAvail = id_ce + (56, )


# Update the Certificate Extensions Map

_certificateExtensionsMapUpdate = {
    id_ce_noRevAvail: univ.Null(),
}

certificateExtensionsMap.update(_certificateExtensionsMapUpdate)
