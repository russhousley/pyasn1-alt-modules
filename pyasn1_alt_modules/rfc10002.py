#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley with assistance from asn1ate v.0.6.0.
#
# Copyright (c) 2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Certificate Management over CMS (CMC)
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc10002.txt
#

from pyasn1.type import char
from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import namedval
from pyasn1.type import opentype
from pyasn1.type import tag
from pyasn1.type import univ
from pyasn1.type import useful

from pyasn1_alt_modules import rfc4211
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import opentypemap


# Since CMS Attributes and CMC Controls both use 'attrType', one map is used

algorithmIdentifierMap = opentypemap.get('algorithmIdentifierMap')

cmsAttributesMap = opentypemap.get('cmsAttributesMap')

cmcControlAttributesMap = cmsAttributesMap

cmsContentTypesMap = opentypemap.get('cmsContentTypesMap')

cmcOtherMessageMap = opentypemap.get('cmcOtherMessageMap')


# Object Identifiers

rsadsi = univ.ObjectIdentifier((1, 2, 840, 113549))

digestAlgorithm = rsadsi + (2, )

id_hmacWithSHA224 = digestAlgorithm + (8, )

id_hmacWithSHA256 = digestAlgorithm + (9, )

id_hmacWithSHA384 = digestAlgorithm + (10, )

id_hmacWithSHA512 = digestAlgorithm + (11, )

id_hmacWithSHA512_224 = digestAlgorithm + (12, )

id_hmacWithSHA512_256 = digestAlgorithm + (13, )


id_pkix = univ.ObjectIdentifier((1, 3, 6, 1, 5, 5, 7))

id_kp = id_pkix + (3, )

id_kp_cmcCA = id_kp + (27, )

id_kp_cmcArchive = id_kp + (29, )


id_cmc = id_pkix + (7, )

id_cmc_statusInfo = id_cmc + (1, )

id_cmc_identification = id_cmc + (2, )

id_cmc_identityProof = id_cmc + (3, )

id_cmc_dataReturn = id_cmc + (4, )

id_cmc_transactionId = id_cmc + (5, )

id_cmc_senderNonce = id_cmc + (6, )

id_cmc_recipientNonce = id_cmc + (7, )

id_cmc_addExtensions = id_cmc + (8, )

id_cmc_encryptedPOP = id_cmc + (9, )

id_cmc_decryptedPOP = id_cmc + (10, )

id_cmc_lraPOPWitness = id_cmc + (11, )

id_cmc_getCert = id_cmc + (15, )

id_cmc_getCRL = id_cmc + (16, )

id_cmc_revokeRequest = id_cmc + (17, )

id_cmc_regInfo = id_cmc + (18, )

id_cmc_responseInfo = id_cmc + (19, )

id_cmc_queryPending = id_cmc + (21, )

id_cmc_popLinkRandom = id_cmc + (22, )

id_cmc_popLinkWitness = id_cmc + (23, )

id_cmc_confirmCertAcceptance = id_cmc + (24, )

id_cmc_statusInfoV2 = id_cmc + (25, )

id_cmc_trustedAnchors = id_cmc + (26, )

id_cmc_authData = id_cmc + (27, )

id_cmc_batchRequests = id_cmc + (28, )

id_cmc_batchResponses = id_cmc + (29, )

id_cmc_publishCert = id_cmc + (30, )

id_cmc_modCertTemplate = id_cmc + (31, )

id_cmc_controlProcessed = id_cmc + (32, )

id_cmc_popLinkWitnessV2 = id_cmc + (33, )

id_cmc_identityProofV2 = id_cmc + (34, )

id_cmc_raIdentityWitness = id_cmc + (35, )

id_cmc_changeSubjectName = id_cmc + (36, )

id_cmc_responseBody = id_cmc + (37, )

id_ExtensionReq = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 14))


id_alg_noSignature = id_pkix + (6, 2)


id_ad = id_pkix + (48, )

id_ad_cmc = id_ad + (12, )


id_cct = id_pkix + (12, )

id_cct_PKIData = id_cct + (2, )

id_cct_PKIResponse = id_cct + (3, )


id_aa = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 16, 2))

id_aa_cmc_unsignedData = id_aa + (34, )


# Upper bounds

MAX = float('inf')

bodyIdMax = univ.Integer(4294967295)


# HMAC Algorithm Identifiers

alg_hMAC_SHA224 = rfc5280.AlgorithmIdentifier()
alg_hMAC_SHA224['algorithm'] = id_hmacWithSHA224
# alg_hMAC_SHA224['parameters'] = univ.Null('')

alg_hMAC_SHA256 = rfc5280.AlgorithmIdentifier()
alg_hMAC_SHA256['algorithm'] = id_hmacWithSHA256
# alg_hMAC_SHA256['parameters'] = univ.Null('')

alg_hMAC_SHA384 = rfc5280.AlgorithmIdentifier()
alg_hMAC_SHA384['algorithm'] = id_hmacWithSHA384
# alg_hMAC_SHA384['parameters'] = univ.Null('')

alg_hMAC_SHA512 = rfc5280.AlgorithmIdentifier()
alg_hMAC_SHA512['algorithm'] = id_hmacWithSHA512
# alg_hMAC_SHA512['parameters'] = univ.Null('')

alg_hMAC_SHA512_224 = rfc5280.AlgorithmIdentifier()
alg_hMAC_SHA512_224['algorithm'] = id_hmacWithSHA512_224
# alg_hMAC_SHA512_224['parameters'] = univ.Null('')

alg_hMAC_SHA512_256 = rfc5280.AlgorithmIdentifier()
alg_hMAC_SHA512_256['algorithm'] = id_hmacWithSHA512_256
# alg_hMAC_SHA512_256['parameters'] = univ.Null('')


# Definitions from RFC XXXX

class AttributeValue(univ.Any):
    pass


class CMCStatus(univ.Integer):
    namedValues = namedval.NamedValues(
        ('success', 0),
        ('failed', 2),
        ('pending', 3),
        ('noSupport', 4),
        ('confirmRequired', 5),
        ('popRequired', 6),
        ('partial', 7)
    )


class CMCFailInfo(univ.Integer):
    namedValues = namedval.NamedValues(
        ('badAlg', 0),
        ('badMessageCheck', 1),
        ('badRequest', 2),
        ('badTime', 3),
        ('badCertId', 4),
        ('unsupportedExt', 5),
        ('mustArchiveKeys', 6),
        ('badIdentity', 7),
        ('popRequired', 8),
        ('popFailed', 9),
        ('noKeyReuse', 10),
        ('internalCAError', 11),
        ('tryLater', 12),
        ('authDataFail', 13)
    )


class ChangeSubjectName(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('subject', rfc5280.Name()),
        namedtype.OptionalNamedType('subjectAlt', rfc5280.GeneralNames().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)))
    )


class PendInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('pendToken', univ.OctetString()),
        namedtype.NamedType('pendTime', useful.GeneralizedTime())
    )


class BodyPartID(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, bodyIdMax)


class BodyPartPath(univ.SequenceOf):
    componentType = BodyPartID()
    sizeSpec = constraint.ValueSizeConstraint(1, MAX)


class BodyPartReference(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('bodyPartID', BodyPartID()),
        namedtype.NamedType('bodyPartPath', BodyPartPath())
    )


class CMCStatusInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('cMCStatus', CMCStatus()),
        namedtype.NamedType('bodyList', univ.SequenceOf(componentType=BodyPartID())),
        namedtype.OptionalNamedType('statusString', char.UTF8String()),
        namedtype.OptionalNamedType(
            'otherInfo', univ.Choice(
                componentType=namedtype.NamedTypes(
                    namedtype.NamedType('failInfo', CMCFailInfo()),
                    namedtype.NamedType('pendInfo', PendInfo())
                )
            )
        )
    )


class CMCStatusInfoV2(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('cMCStatus', CMCStatus()),
        namedtype.NamedType('bodyList', univ.SequenceOf(componentType=BodyPartReference())),
        namedtype.OptionalNamedType('statusString', char.UTF8String()),
        namedtype.OptionalNamedType(
            'otherInfo', univ.Choice(
                componentType=namedtype.NamedTypes(
                    namedtype.NamedType('failInfo', CMCFailInfo()),
                    namedtype.NamedType('pendInfo', PendInfo()),
                    namedtype.NamedType(
                        'extendedFailInfo', univ.Sequence(
                        componentType=namedtype.NamedTypes(
                            namedtype.NamedType('failInfoOID', univ.ObjectIdentifier()),
                            namedtype.NamedType('failInfoValue', AttributeValue()))
                        ).subtype(implicitTag=tag.Tag(
                            tag.tagClassContext, tag.tagFormatConstructed, 1))
                    )
                )
            )
        )
    )


class GetCRL(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('issuerName', rfc5280.Name()),
        namedtype.OptionalNamedType('cRLName', rfc5280.GeneralName()),
        namedtype.OptionalNamedType('time', useful.GeneralizedTime()),
        namedtype.OptionalNamedType('reasons', rfc5280.ReasonFlags())
    )


class PopLinkWitnessV2(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('keyGenAlgorithm', rfc5280.AlgorithmIdentifier()),
        namedtype.NamedType('macAlgorithm', rfc5280.AlgorithmIdentifier()),
        namedtype.NamedType('witness', univ.OctetString())
    )


class ControlsProcessed(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('bodyList',
            univ.SequenceOf(componentType=BodyPartReference()))
    )


class CertificationRequest(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('certificationRequestInfo', univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('version', univ.Integer()),
                namedtype.NamedType('subject', rfc5280.Name()),
                namedtype.NamedType('subjectPublicKeyInfo', univ.Sequence(
                    componentType=namedtype.NamedTypes(
                        namedtype.NamedType('algorithm', rfc5280.AlgorithmIdentifier()),
                        namedtype.NamedType('subjectPublicKey', univ.BitString())))),
                namedtype.NamedType('attributes', univ.SetOf(
                    componentType=rfc5652.Attribute()).subtype(implicitTag=tag.Tag(
                        tag.tagClassContext, tag.tagFormatSimple, 0)))))),
        namedtype.NamedType('signatureAlgorithm', rfc5280.AlgorithmIdentifier()),
        namedtype.NamedType('signature', univ.BitString())
    )


class TaggedCertificationRequest(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('bodyPartID', BodyPartID()),
        namedtype.NamedType('certificationRequest', CertificationRequest())
    )


class TaggedRequest(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tcr', TaggedCertificationRequest().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.NamedType('crm', rfc4211.CertReqMsg().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
        namedtype.NamedType('orm', univ.Sequence(componentType=namedtype.NamedTypes(
            namedtype.NamedType('bodyPartID', BodyPartID()),
            namedtype.NamedType('requestMessageType', univ.ObjectIdentifier()),
            namedtype.NamedType('requestMessageValue', univ.Any())
        )).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)))
    )


class PublishTrustAnchors(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('seqNumber', univ.Integer()),
        namedtype.NamedType('hashAlgorithm', rfc5280.AlgorithmIdentifier()),
        namedtype.NamedType('anchorHashes', univ.SequenceOf(
            componentType=univ.OctetString()))
    )


class RevokeRequest(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('issuerName', rfc5280.Name()),
        namedtype.NamedType('serialNumber', univ.Integer()),
        namedtype.NamedType('reason', rfc5280.CRLReason()),
        namedtype.OptionalNamedType('invalidityDate', useful.GeneralizedTime()),
        namedtype.OptionalNamedType('passphrase', univ.OctetString()),
        namedtype.OptionalNamedType('comment', char.UTF8String())
    )


class TaggedContentInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('bodyPartID', BodyPartID()),
        namedtype.NamedType('contentInfo', rfc5652.ContentInfo())
    )


class IdentifyProofV2(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('proofAlgID', rfc5280.AlgorithmIdentifier()),
        namedtype.NamedType('macAlgId', rfc5280.AlgorithmIdentifier()),
        namedtype.NamedType('witness', univ.OctetString())
    )


class CMCPublicationInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('hashAlg', rfc5280.AlgorithmIdentifier()),
        namedtype.NamedType('certHashes', univ.SequenceOf(
            componentType=univ.OctetString())),
        namedtype.NamedType('pubInfo', rfc4211.PKIPublicationInfo())
    )


class DecryptedPOP(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('bodyPartID', BodyPartID()),
        namedtype.NamedType('thePOPAlgID', rfc5280.AlgorithmIdentifier()),
        namedtype.NamedType('thePOP', univ.OctetString())
    )


class TaggedAttribute(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('bodyPartID', BodyPartID()),
        namedtype.NamedType('attrType', univ.ObjectIdentifier()),
        namedtype.NamedType('attrValues', univ.SetOf(componentType=AttributeValue()),
            openType=opentype.OpenType('attrType', cmcControlAttributesMap)
        )
    )


class OtherMsg(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('bodyPartID', BodyPartID()),
        namedtype.NamedType('otherMsgType', univ.ObjectIdentifier()),
        namedtype.NamedType('otherMsgValue', univ.Any(),
            openType=opentype.OpenType('attrType', cmcOtherMessageMap)
        )
    )


class PKIData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('controlSequence', univ.SequenceOf(
            componentType=TaggedAttribute())),
        namedtype.NamedType('reqSequence', univ.SequenceOf(
            componentType=TaggedRequest())),
        namedtype.NamedType('cmsSequence', univ.SequenceOf(
            componentType=TaggedContentInfo())),
        namedtype.NamedType('otherMsgSequence', univ.SequenceOf(
            componentType=OtherMsg()))
    )


class BodyPartList(univ.SequenceOf):
    componentType = BodyPartID()
    sizeSpec = constraint.ValueSizeConstraint(1, MAX)


class AuthPublish(BodyPartID):
    pass


class CMCUnsignedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('bodyPartPath', BodyPartPath()),
        namedtype.NamedType('identifier', univ.ObjectIdentifier()),
        namedtype.NamedType('content', univ.Any())
    )


class CMCCertId(rfc5652.IssuerAndSerialNumber):
    pass


class PKIResponse(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('controlSequence', univ.SequenceOf(
            componentType=TaggedAttribute())),
        namedtype.NamedType('cmsSequence', univ.SequenceOf(
            componentType=TaggedContentInfo())),
        namedtype.NamedType('otherMsgSequence', univ.SequenceOf(
            componentType=OtherMsg()))
    )


class ResponseBody(PKIResponse):
    pass


class ModCertTemplate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('pkiDataReference', BodyPartPath()),
        namedtype.NamedType('certReferences', BodyPartList()),
        namedtype.DefaultedNamedType('replace', univ.Boolean().subtype(value=1)),
        namedtype.NamedType('certTemplate', rfc4211.CertTemplate())
    )


class ExtensionReq(univ.SequenceOf):
    componentType = rfc5280.Extension()
    sizeSpec = constraint.ValueSizeConstraint(1, MAX)


class LraPopWitness(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('pkiDataBodyid', BodyPartID()),
        namedtype.NamedType('bodyIds', univ.SequenceOf(componentType=BodyPartID()))
    )


class GetCert(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('issuerName', rfc5280.GeneralName()),
        namedtype.NamedType('serialNumber', univ.Integer())
    )


class AddExtensions(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('pkiDataReference', BodyPartID()),
        namedtype.NamedType('certReferences', univ.SequenceOf(
            componentType=BodyPartID())),
        namedtype.NamedType('extensions', univ.SequenceOf(
            componentType=rfc5280.Extension()))
    )


class EncryptedPOP(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('request', TaggedRequest()),
        namedtype.NamedType('cms', rfc5652.ContentInfo()),
        namedtype.NamedType('thePOPAlgID', rfc5280.AlgorithmIdentifier()),
        namedtype.NamedType('witnessAlgID', rfc5280.AlgorithmIdentifier()),
        namedtype.NamedType('witness', univ.OctetString())
    )


class NoSignatureValue(univ.OctetString):
    pass


# Update the CMC Control Attributes Map (a.k.a. CMS Attributes Map)

_cmcControlAttributesMapUpdate = {
    id_cmc_statusInfo: CMCStatusInfo(),
    id_cmc_statusInfoV2: CMCStatusInfoV2(),
    id_cmc_identification: char.UTF8String(),
    id_cmc_identityProof: univ.OctetString(),
    id_cmc_identityProofV2: IdentifyProofV2(),
    id_cmc_dataReturn: univ.OctetString(),
    id_cmc_transactionId: univ.Integer(),
    id_cmc_senderNonce: univ.OctetString(),
    id_cmc_recipientNonce: univ.OctetString(),
    id_cmc_addExtensions: AddExtensions(),
    id_cmc_encryptedPOP: EncryptedPOP(),
    id_cmc_decryptedPOP: DecryptedPOP(),
    id_cmc_lraPOPWitness: LraPopWitness(),
    id_cmc_getCert: GetCert(),
    id_cmc_getCRL: GetCRL(),
    id_cmc_revokeRequest: RevokeRequest(),
    id_cmc_regInfo: univ.OctetString(),
    id_cmc_responseInfo: univ.OctetString(),
    id_cmc_queryPending: univ.OctetString(),
    id_cmc_popLinkRandom: univ.OctetString(),
    id_cmc_popLinkWitness: univ.OctetString(),
    id_cmc_popLinkWitnessV2: PopLinkWitnessV2(),
    id_cmc_confirmCertAcceptance: CMCCertId(),
    id_cmc_trustedAnchors: PublishTrustAnchors(),
    id_cmc_authData: AuthPublish(),
    id_cmc_batchRequests: BodyPartList(),
    id_cmc_batchResponses: BodyPartList(),
    id_cmc_publishCert: CMCPublicationInfo(),
    id_cmc_modCertTemplate: ModCertTemplate(),
    id_cmc_controlProcessed: ControlsProcessed(),
    id_ExtensionReq: ExtensionReq(),
}

cmcControlAttributesMap.update(_cmcControlAttributesMapUpdate)


# Update the CMS Content Type Map

_cmsContentTypesMapUpdate = {
    id_cct_PKIData: PKIData(),
    id_cct_PKIResponse: PKIResponse(),
}

cmsContentTypesMap.update(_cmsContentTypesMapUpdate)


# Update the Algorithm Identifier Map

_algorithmIdentifierMapUpdate = {
    id_hmacWithSHA224: univ.Null(),
    id_hmacWithSHA256: univ.Null(),
    id_hmacWithSHA384: univ.Null(),
    id_hmacWithSHA512: univ.Null(),
    id_hmacWithSHA512_224: univ.Null(),
    id_hmacWithSHA512_256: univ.Null(),
}
