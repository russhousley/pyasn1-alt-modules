#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2025, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Digital Signatures on RPSL End-Site Prefix Lengths
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9977.txt
#

from pyasn1.type import char
from pyasn1.type import univ

from pyasn1_alt_modules import opentypemap

cmsContentTypesMap = opentypemap.get('cmsContentTypesMap')


# CMS Content Type for Geofeed CSV with CRLF

id_ct = univ.ObjectIdentifier('1.2.840.113549.1.9.16.1')

id_ct_prefixlenCSVwithCRLF = id_ct + (57, )


# Update the CMS Content Type Map

_cmsContentTypesMapUpdate = {
    id_ct_prefixlenCSVwithCRLF: char.UTF8String(),
}

cmsContentTypesMap.update(_cmsContentTypesMapUpdate)
