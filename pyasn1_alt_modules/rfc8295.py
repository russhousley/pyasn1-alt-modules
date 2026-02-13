#
# This file is part of pyasn1-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2025-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Enrollment over Secure Transport (EST) Extensions
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc8295.txt
# https://www.rfc-editor.org/rfc/rfc6402.txt
# https://www.rfc-editor.org/rfc/rfc2985.txt
#

from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ

from pyasn1_alt_modules import rfc2985
from pyasn1_alt_modules import rfc4211
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc6402


# Imports from RFC 5280

id_pkix = rfc5280.id_pkix


# Imports from RFC 5652

ContentInfo = rfc5652.ContentInfo


# Imports from RFC 2985 for PKCS #7 PDU  

pkcs_9_at_pkcs7PDU = rfc2985.pkcs_9_at_pkcs7PDU

pKCS7PDU = rfc2985.pKCS7PDU


# Import from RFC 4211

CertReqMsg = rfc4211.CertReqMsg


# Imports from RFC 6402

id_cct = rfc6402.id_cct

id_cct_PKIData = rfc6402.id_cct_PKIData

bodyIdMax = rfc6402.bodyIdMax

BodyPartID = rfc6402.BodyPartID

CertificationRequest = rfc6402.CertificationRequest

TaggedCertificationRequest = rfc6402.TaggedCertificationRequest


# This allows a small subset of TaggedRequest as defined in RFC 6402

class TaggedRequest(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tcr', TaggedCertificationRequest().subtype(
            implicitTag=tag.Tag(tag.tagClassContext,
                tag.tagFormatConstructed, 0))),
        namedtype.NamedType('crm', CertReqMsg().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)))
    )


# This allows a small subset of PKIData as defined in RFC 6402

class PKIData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('reqSequence',
            univ.SequenceOf(componentType=TaggedRequest())))


# Do not update the CMS Content Types map.  Note that rfc6402.py defines
# PKIData, and the subset used here will properly decode using the
# entry in the CMS Content Types map that is added by rfc6402.py.
