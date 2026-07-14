#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# RATS Conceptual Messages Wrapper (CMW)
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9999.txt
#

from pyasn1.type import char
from pyasn1.type import namedtype
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import opentypemap

certificateExtensionsMap = opentypemap.get('certificateExtensionsMap')


# RATS Conceptual Messages Wrapper (CMW)

id_pe_cmw = rfc5280.id_pe + (35, )


class CMW(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('json', char.UTF8String()),
        namedtype.NamedType('cbor', univ.OctetString())
    )


# Conceptual Messages Wrapper (CMW) Collection Extension

ext_CMW = rfc5280.Extension()
ext_CMW['extnID'] = id_pe_cmw
ext_CMW['critical'] = 0
ext_CMW['extnValue'] = univ.OctetString() # contains DER-encoded CMW()


# Update the Certificate Extension Map

_certificateExtensionsMapUpdate = {
    id_pe_cmw: CMW(),
}

certificateExtensionsMap.update(_certificateExtensionsMapUpdate)
