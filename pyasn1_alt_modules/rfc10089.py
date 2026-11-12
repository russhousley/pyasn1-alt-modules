#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# STIR OCSP Telephone Number Query Extension
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc10089.txt
#

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc8226
from pyasn1_alt_modules import opentypemap

certificateExtensionsMap = opentypemap.get('certificateExtensionsMap')


# Imports from RFC 5280

id_ad_ocsp = rfc5280.id_ad_ocsp


# Imports from RFC 8226

TelephoneNumber = rfc8226.TelephoneNumber


# Definitions from RFC 10089

id_pkix_ocsp = id_ad_ocsp

id_pkix_ocsp_stir_tn = id_pkix_ocsp + (10, )


class TNQuery(TelephoneNumber):
    pass


# Update the Certificate Extension Map, which is used for OCSP extensions too

_certificateExtensionsMapUpdate = {
    id_pkix_ocsp_stir_tn: TNQuery(),
}

certificateExtensionsMap.update(_certificateExtensionsMapUpdate)
