#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# A Voucher Artifact for Bootstrapping Protocols
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc8366.txt
#

from pyasn1.type import char
from pyasn1.type import univ

from pyasn1_alt_modules import opentypemap

cmsContentTypesMap = opentypemap.get('cmsContentTypesMap')


# A Voucher Artifact for Bootstrapping Protocols is a JSON object

id_ct = univ.ObjectIdentifier('1.2.840.113549.1.9.16.1')

id_ct_animaJSONVoucher = id_ct + (40, )


# Update the CMS Content Type Map

_cmsContentTypesMapUpdate = {
    id_ct_animaJSONVoucher: char.UTF8String(),
}

cmsContentTypesMap.update(_cmsContentTypesMapUpdate)
