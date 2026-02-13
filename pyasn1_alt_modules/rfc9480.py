#
# This file is part of pyasn1_alt_modules software.
#
# Created by Russ Housley with minor assistance from asn1ate v.0.6.0.
# Modified by Russ Housley to make InfoTypeAndValue['infoType'] optional.
# Modified by Russ Housley to update the algorithmIdentifierMap.
# Modified bt Russ Housley to correct typo in SignKeyPairTypesValue.
# Modified by Guiliano Lehmann to correct CertProfileValue, CRLSource,
#   CertResponse and CertRepMessage.
#
# Copyright (c) 2021-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1_alt_modules_license.txt
#
# Updates to the Certificate Management Protocol (CMP)
#
# ASN.1 source from:
# https://www.rfc_editor.org/rfc/rfc9480.txt
#

from pyasn1.type import char
from pyasn1.type import constraint
from pyasn1.type import namedval
from pyasn1.type import namedtype
from pyasn1.type import opentype
from pyasn1.type import tag
from pyasn1.type import univ
from pyasn1.type import useful

from pyasn1_alt_modules import rfc2985
from pyasn1_alt_modules import rfc4210
from pyasn1_alt_modules import rfc4211
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc6402
from pyasn1_alt_modules import opentypemap

algorithmIdentifierMap = opentypemap.get('algorithmIdentifierMap')

cmpInfoTypeAndValueMap = opentypemap.get('cmpInfoTypeAndValueMap')

cmsAttributesMap = opentypemap.get('cmsAttributesMap')

MAX = float('inf')


# Imports from RFC 5280

Certificate = rfc5280.Certificate

CertificateList = rfc5280.CertificateList

DistributionPointName = rfc5280.DistributionPointName

Extensions = rfc5280.Extensions

Name = rfc5280.Name

AlgorithmIdentifier = rfc5280.AlgorithmIdentifier

GeneralNames = rfc5280.GeneralNames

GeneralName = rfc5280.GeneralName

KeyIdentifier = rfc5280.KeyIdentifier

Time = rfc5280.Time

id_pkix = rfc5280.id_pkix

id_kp = rfc5280.id_kp


# Imports from RFC 4211

CertTemplate = rfc4211.CertTemplate

PKIPublicationInfo = rfc4211.PKIPublicationInfo

EncryptedKey = rfc4211.EncryptedKey

CertId = rfc4211.CertId

CertReqMessages = rfc4211.CertReqMessages

Controls = rfc4211.Controls

AttributeTypeAndValue = rfc4211.AttributeTypeAndValue

id_regCtrl = rfc4211.id_regCtrl


# Imports from RFC 5652

Attribute = rfc5652.Attribute

EnvelopedData = rfc5652.EnvelopedData

SignedData = rfc5652.SignedData


# Imports from RFC 6402

CertificationRequest = rfc6402.CertificationRequest

id_kp_cmcCA = rfc6402.id_kp_cmcCA

id_kp_cmcRA  = rfc6402.id_kp_cmcRA


# Imports from RFC 2985

pkcs_9 = rfc2985.pkcs_9

pkcs_9_at_localKeyId = rfc2985.pkcs_9_at_localKeyId


# Updates to the Certificate Management Protocol (CMP)
# Where possible, just import from RFC 4210

CMPCertificate = rfc4210.CMPCertificate


OOBCert = rfc4210.OOBCert


CertAnnContent = rfc4210.CertAnnContent


PollRepContent = rfc4210.PollRepContent


PKIConfirmContent = rfc4210.PKIConfirmContent


CRLAnnContent = rfc4210.CRLAnnContent


CAKeyUpdAnnContent = rfc4210.CAKeyUpdAnnContent


RevDetails = rfc4210.RevDetails


RevReqContent = rfc4210.RevReqContent


class InfoTypeAndValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('infoType', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType('infoValue', univ.Any(),
                                    openType=opentype.OpenType('infoType', cmpInfoTypeAndValueMap))
    )


class GenRepContent(univ.SequenceOf):
    componentType = InfoTypeAndValue()


class GenMsgContent(univ.SequenceOf):
    componentType = InfoTypeAndValue()


POPODecKeyRespContent = rfc4210.POPODecKeyRespContent


Challenge = rfc4210.Challenge


# Added in CMP Updates
#
class Rand(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('int', univ.Integer()),
        namedtype.NamedType('sender', GeneralName())
    )


PKIStatus = rfc4210.PKIStatus


PKIFailureInfo = rfc4210.PKIFailureInfo


RevAnnContent = rfc4210.RevAnnContent


RevRepContent = rfc4210.RevRepContent


KeyRecRepContent = rfc4210.KeyRecRepContent


POPODecKeyChallContent = rfc4210.POPODecKeyChallContent


OOBCertHash = rfc4210.OOBCertHash


DHBMParameter = rfc4210.DHBMParameter


PBMParameter = rfc4210.PBMParameter


PKIProtection = rfc4210.PKIProtection


class PKIFreeText(univ.SequenceOf):
    componentType = char.UTF8String()
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


class PKIStatusInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('status', PKIStatus()),
        namedtype.OptionalNamedType('statusString', PKIFreeText()),
        namedtype.OptionalNamedType('failInfo', PKIFailureInfo())
    )


class CertOrEncCert(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('certificate', CMPCertificate().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 0))),
        namedtype.NamedType('encryptedCert', EncryptedKey().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatSimple, 1)))
    )


class CertifiedKeyPair(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('certOrEncCert', CertOrEncCert()),
        namedtype.OptionalNamedType('privateKey',
                                    EncryptedKey().subtype(explicitTag=tag.Tag(
                                        tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType('publicationInfo',
                                    PKIPublicationInfo().subtype(explicitTag=tag.Tag(
                                        tag.tagClassContext, tag.tagFormatSimple, 1)))
    )


class CertResponse(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('certReqId', univ.Integer()),
        namedtype.NamedType('status', PKIStatusInfo()),
        namedtype.OptionalNamedType('certifiedKeyPair', CertifiedKeyPair()),
        namedtype.OptionalNamedType('rspInfo', univ.OctetString())
    )


class CertRepMessage(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('caPubs', univ.SequenceOf(
            componentType=CMPCertificate()).subtype(
            sizeSpec=constraint.ValueSizeConstraint(1, MAX),
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 1))),
        namedtype.NamedType('response', univ.SequenceOf(
            componentType=CertResponse()))
    )


class ErrorMsgContent(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('pKIStatusInfo', PKIStatusInfo()),
        namedtype.OptionalNamedType('errorCode', univ.Integer()),
        namedtype.OptionalNamedType('errorDetails', PKIFreeText())
    )


PollReqContent = rfc4210.PollReqContent


class PollRepContent(univ.SequenceOf):
    componentType = univ.Sequence(componentType=namedtype.NamedTypes(
        namedtype.NamedType('certReqId', univ.Integer()),
        namedtype.NamedType('checkAfter', univ.Integer()),
        namedtype.OptionalNamedType('reason', PKIFreeText())
    ))


class CertStatus(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('hashAlg',
                                    AlgorithmIdentifier().subtype(explicitTag=tag.Tag(
                                        tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('certHash', univ.OctetString()),
        namedtype.NamedType('certReqId', univ.Integer()),
        namedtype.OptionalNamedType('statusInfo', PKIStatusInfo())
    )


class CertConfirmContent(univ.SequenceOf):
    componentType = CertStatus()


class PKIHeader(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('pvno', univ.Integer(
            namedValues=namedval.NamedValues(
                ('cmp1999', 1), ('cmp2000', 2), ('cmp2021', 3)))),
        namedtype.NamedType('sender', GeneralName()),
        namedtype.NamedType('recipient', GeneralName()),
        namedtype.OptionalNamedType('messageTime',
                                    useful.GeneralizedTime().subtype(explicitTag=tag.Tag(
                                        tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType('protectionAlg',
                                    AlgorithmIdentifier().subtype(explicitTag=tag.Tag(
                                        tag.tagClassContext, tag.tagFormatSimple, 1))),
        namedtype.OptionalNamedType('senderKID',
                                    KeyIdentifier().subtype(explicitTag=tag.Tag(
                                        tag.tagClassContext, tag.tagFormatSimple, 2))),
        namedtype.OptionalNamedType('recipKID',
                                    KeyIdentifier().subtype(explicitTag=tag.Tag(
                                        tag.tagClassContext, tag.tagFormatSimple, 3))),
        namedtype.OptionalNamedType('transactionID',
                                    univ.OctetString().subtype(explicitTag=tag.Tag(
                                        tag.tagClassContext, tag.tagFormatSimple, 4))),
        namedtype.OptionalNamedType('senderNonce',
                                    univ.OctetString().subtype(explicitTag=tag.Tag(
                                        tag.tagClassContext, tag.tagFormatSimple, 5))),
        namedtype.OptionalNamedType('recipNonce',
                                    univ.OctetString().subtype(explicitTag=tag.Tag(
                                        tag.tagClassContext, tag.tagFormatSimple, 6))),
        namedtype.OptionalNamedType('freeText',
                                    PKIFreeText().subtype(explicitTag=tag.Tag(
                                        tag.tagClassContext, tag.tagFormatSimple, 7))),
        namedtype.OptionalNamedType('generalInfo',
                                    univ.SequenceOf(componentType=InfoTypeAndValue()).subtype(
                                        subtypeSpec=constraint.ValueSizeConstraint(1, MAX)).subtype(
                                        explicitTag=tag.Tag(tag.tagClassContext,
                                                            tag.tagFormatSimple, 8)))
    )


# Since pyasn1 does not naturally handle recursive definitions, this hack
# instead of:
#     class NestedMessageContent(PKIMessages):
#         pass
# Note that there is a second part of the hack at the bottom of the module.
#
class NestedMessageContent(univ.SequenceOf):
    componentType = univ.Any()


nestedMessageContent = NestedMessageContent().subtype(
    explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 20))


class PKIBody(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('ir', CertReqMessages().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatSimple, 0))),
        namedtype.NamedType('ip', CertRepMessage().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 1))),
        namedtype.NamedType('cr', CertReqMessages().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatSimple, 2))),
        namedtype.NamedType('cp', CertRepMessage().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 3))),
        namedtype.NamedType('p10cr', CertificationRequest().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatSimple, 4))),
        namedtype.NamedType('popdecc', POPODecKeyChallContent().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatSimple, 5))),
        namedtype.NamedType('popdecr', POPODecKeyRespContent().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatSimple, 6))),
        namedtype.NamedType('kur', CertReqMessages().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatSimple, 7))),
        namedtype.NamedType('kup', CertRepMessage().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 8))),
        namedtype.NamedType('krr', CertReqMessages().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatSimple, 9))),
        namedtype.NamedType('krp', KeyRecRepContent().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 10))),
        namedtype.NamedType('rr', RevReqContent().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatSimple, 11))),
        namedtype.NamedType('rp', RevRepContent().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 12))),
        namedtype.NamedType('ccr', CertReqMessages().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatSimple, 13))),
        namedtype.NamedType('ccp', CertRepMessage().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 14))),
        namedtype.NamedType('ckuann', CAKeyUpdAnnContent().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 15))),
        namedtype.NamedType('cann', CertAnnContent().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 16))),
        namedtype.NamedType('rann', RevAnnContent().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 17))),
        namedtype.NamedType('crlann', CRLAnnContent().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatSimple, 18))),
        namedtype.NamedType('pkiconf', PKIConfirmContent().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatSimple, 19))),
        namedtype.NamedType('nested', nestedMessageContent),
        namedtype.NamedType('genm', GenMsgContent().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatSimple, 21))),
        namedtype.NamedType('genp', GenRepContent().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatSimple, 22))),
        namedtype.NamedType('error', ErrorMsgContent().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 23))),
        namedtype.NamedType('certConf', CertConfirmContent().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatSimple, 24))),
        namedtype.NamedType('pollReq', PollReqContent().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatSimple, 25))),
        namedtype.NamedType('pollRep', PollRepContent().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatSimple, 26)))
    )


class PKIMessage(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('header', PKIHeader()),
        namedtype.NamedType('body', PKIBody()),
        namedtype.OptionalNamedType('protection', PKIProtection().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType('extraCerts', univ.SequenceOf(
            componentType=CMPCertificate()).subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, MAX)).subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatSimple, 1)))
    )


class PKIMessages(univ.SequenceOf):
    componentType = PKIMessage()
    subtypeSpec=constraint.ValueSizeConstraint(1, MAX)


class ProtectedPart(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('header', PKIHeader()),
        namedtype.NamedType('body', PKIBody())
    )


# Added in CMP Updates
#
class RootCaKeyUpdateContent(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('newWithNew', CMPCertificate()),
        namedtype.OptionalNamedType('newWithOld', CMPCertificate().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 0))),
        namedtype.OptionalNamedType('oldWithNew', CMPCertificate().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 1)))
    )


# Added in CMP Updates
#
class CRLSource(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('dpn', DistributionPointName().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 0))),
        namedtype.NamedType('issuer', GeneralNames().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 1)))
    )


# Added in CMP Updates
#
class CRLStatus(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('source', CRLSource()),
        namedtype.OptionalNamedType('thisUpdate', Time())
    )


# Added in CMP Updates
#
class CertReqTemplateContent(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('certTemplate', CertTemplate()),
        namedtype.OptionalNamedType('keySpec', Controls())
    )


# Object Identifiers for MAC algorithms

id_DHBasedMac = rfc4210.id_DHBasedMac

id_PasswordBasedMac = rfc4210.id_PasswordBasedMac


# Extended Key Usage extension for PKI entities used in CMP operations

id_kp_cmKGA = id_kp + (32,)


# The value for the LocalKeyId Attribute from PKCS#9 (RFC 2985)

class LocalKeyIdValue(univ.OctetString):
    pass


# Additional CRMF Registration Controls

id_regCtrl_altCertTemplate = id_regCtrl + (7,)

class AltCertTemplate(AttributeTypeAndValue):
    pass


id_regCtrl_algId = id_regCtrl + (11,)

class AlgIdCtrl(AlgorithmIdentifier):
    pass


id_regCtrl_rsaKeyLen = id_regCtrl + (12,)

class RsaKeyLenCtrl(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(1, MAX)


# CMP Information Types

id_it = id_pkix + (4,)

id_it_caProtEncCert = id_it + (1,)

class CAProtEncCertValue(CMPCertificate):
    pass


id_it_signKeyPairTypes = id_it + (2,)

class SignKeyPairTypesValue(univ.SequenceOf):
    componentType = AlgorithmIdentifier()


id_it_encKeyPairTypes = id_it + (3,)

class EncKeyPairTypesValue(univ.SequenceOf):
    componentType = AlgorithmIdentifier()


id_it_preferredSymmAlg = id_it + (4,)

class PreferredSymmAlgValue(AlgorithmIdentifier):
    pass


id_it_caKeyUpdateInfo = id_it + (5,)

class CAKeyUpdateInfoValue(CAKeyUpdAnnContent):
    pass


id_it_currentCRL = id_it + (6,)

class CurrentCRLValue(CertificateList):
    pass


id_it_unsupportedOIDs = id_it + (7,)

class UnsupportedOIDsValue(univ.SequenceOf):
    componentType = univ.ObjectIdentifier()


id_it_keyPairParamReq = id_it + (10,)

class KeyPairParamReqValue(univ.ObjectIdentifier):
    pass


id_it_keyPairParamRep = id_it + (11,)

class KeyPairParamRepValue(AlgorithmIdentifier):
    pass


id_it_revPassphrase = id_it + (12,)

class RevPassphraseValue(EncryptedKey):
    pass


id_it_implicitConfirm = id_it + (13,)

class ImplicitConfirmValue(univ.Null):
    pass


id_it_confirmWaitTime = id_it + (14,)

class ConfirmWaitTimeValue(useful.GeneralizedTime):
    pass


id_it_origPKIMessage = id_it + (15,)

class OrigPKIMessageValue(PKIMessages):
    pass


id_it_suppLangTags = id_it + (16,)

class SuppLangTagsValue(univ.SequenceOf):
    componentType = char.UTF8String()


# Added in CMP Updates
#
id_it_caCerts = id_it + (17,)

class CaCertsValue(univ.SequenceOf):
    componentType = CMPCertificate()


# Added in CMP Updates
#
id_it_rootCaKeyUpdate = id_it + (18,)

class RootCaKeyUpdateValue(RootCaKeyUpdateContent):
    pass


# Added in CMP Updates
#
id_it_certReqTemplate = id_it + (19,)

class CertReqTemplateValue(CertReqTemplateContent):
    pass


# Added in CMP Updates
#
id_it_rootCaCert = id_it + (20,)

class RootCaCertValue(CMPCertificate):
    pass


# Added in CMP Updates
#
id_it_certProfile = id_it + (21,)

class CertProfileValue(univ.SequenceOf):
    componentType = char.UTF8String()
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


# Added in CMP Updates
#
id_it_crlStatusList = id_it + (22,)

class CRLStatusListValue(univ.SequenceOf):
    componentType = CRLStatus()
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


# Added in CMP Updates
#
id_it_crls = id_it + (23,)

class CRLsValue(univ.SequenceOf):
    componentType = CertificateList()
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


# Update the CMP Information Types Map

_cmpInfoTypeAndValueMapUpdate = {
    id_it_caProtEncCert: CAProtEncCertValue(),
    id_it_signKeyPairTypes: SignKeyPairTypesValue(),
    id_it_encKeyPairTypes: EncKeyPairTypesValue(),
    id_it_preferredSymmAlg: PreferredSymmAlgValue(),
    id_it_caKeyUpdateInfo: CAKeyUpdateInfoValue(),
    id_it_currentCRL: CurrentCRLValue(),
    id_it_unsupportedOIDs: UnsupportedOIDsValue(),
    id_it_keyPairParamReq: KeyPairParamReqValue(),
    id_it_keyPairParamRep: KeyPairParamRepValue(),
    id_it_revPassphrase: RevPassphraseValue(),
    id_it_implicitConfirm: ImplicitConfirmValue(),
    id_it_confirmWaitTime: ConfirmWaitTimeValue(),
    id_it_origPKIMessage: OrigPKIMessageValue(),
    id_it_suppLangTags: SuppLangTagsValue(),
    id_it_caCerts: CaCertsValue(),
    id_it_rootCaKeyUpdate: RootCaKeyUpdateValue(),
    id_it_certReqTemplate: CertReqTemplateValue(),
    id_it_rootCaCert: RootCaCertValue(),
    id_it_certProfile: CertProfileValue(),
    id_it_crlStatusList: CRLStatusListValue(),
    id_it_crls: CRLsValue(),
}

cmpInfoTypeAndValueMap.update(_cmpInfoTypeAndValueMapUpdate)


# Update the CMS Attribute Map

_cmsAttributesMapUpdate = {
    id_regCtrl_altCertTemplate: AltCertTemplate(),
    id_regCtrl_algId: AlgIdCtrl(),
    id_regCtrl_rsaKeyLen: RsaKeyLenCtrl(),
}

cmsAttributesMap.update(_cmsAttributesMapUpdate)


# Update the Algorithm Identifier map

_algorithmIdentifierMapUpdate = {
    id_PasswordBasedMac: PBMParameter(),
    id_DHBasedMac: DHBMParameter(),
}

algorithmIdentifierMap.update(_algorithmIdentifierMapUpdate)


# Since pyasn1 does not naturally handle recursive definitions, this hack:
#
NestedMessageContent._componentType = PKIMessages()
nestedMessageContent._componentType = PKIMessages()
