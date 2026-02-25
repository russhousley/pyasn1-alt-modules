#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# CMS content types for PKCS#8 version 2
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9939.txt

from pyasn1.type import univ

from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc5958
from pyasn1_alt_modules import opentypemap

cmsContentTypesMap = opentypemap.get('cmsContentTypesMap')


# Imports from RFC 5958

PrivateKeyInfo = rfc5958.PrivateKeyInfo

EncryptedPrivateKeyInfo = rfc5958.EncryptedPrivateKeyInfo


# CMS Content Type Identifiers

id_ct = univ.ObjectIdentifier('1.2.840.113549.1.9.16.1')

id_ct_privateKeyInfo = id_ct + (52,)

id_ct_encrPrivateKeyInfo = id_ct + (53,)


# CMS Content Types

ct_privateKeyInfo = rfc5652.ContentInfo()
ct_privateKeyInfo['contentType'] = id_ct_privateKeyInfo
ct_privateKeyInfo['content'] = PrivateKeyInfo()

ct_encrPrivateKeyInfo = rfc5652.ContentInfo()
ct_encrPrivateKeyInfo['contentType'] = id_ct_encrPrivateKeyInfo
ct_encrPrivateKeyInfo['content'] = EncryptedPrivateKeyInfo()


# Update the CMS Content Types Map

_cmsContentTypesMapUpdate = {
    id_ct_privateKeyInfo: PrivateKeyInfo(),
    id_ct_encrPrivateKeyInfo: EncryptedPrivateKeyInfo(),
}

cmsContentTypesMap.update(_cmsContentTypesMapUpdate)
