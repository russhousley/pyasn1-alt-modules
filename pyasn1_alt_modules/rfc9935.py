#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# ML-KEM Algorithm Identifiers for use in X.509 Certificates
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9935.txt
#

from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280


# Imports from RFC 5280

AlgorithmIdentifier = rfc5280.AlgorithmIdentifier

SubjectPublicKeyInfo = rfc5280.SubjectPublicKeyInfo


# Object Identifiers

nistAlgorithms = univ.ObjectIdentifier('2.16.840.1.101.3.4')

kems = nistAlgorithms + (4, )

id_alg_ml_kem_512 = kems + (1, )

id_alg_ml_kem_768 = kems + (2, )

id_alg_ml_kem_1024 = kems + (3, )


# ML-KEM Algorithm Private Keys

class ML_KEM_512_PrivateKey(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('seed', univ.OctetString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(64, 64)).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('expandedKey', univ.OctetString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1632, 1632))),
        namedtype.NamedType('both', univ.Sequence(componentType=namedtype.NamedTypes(
            namedtype.NamedType('seed', univ.OctetString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(64, 64))),
            namedtype.NamedType('expandedKey', univ.OctetString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1632, 1632)))
        )))
    )


class ML_KEM_768_PrivateKey(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('seed', univ.OctetString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(64, 64)).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('expandedKey', univ.OctetString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(2400, 2400))),
        namedtype.NamedType('both', univ.Sequence(componentType=namedtype.NamedTypes(
            namedtype.NamedType('seed', univ.OctetString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(64, 64))),
            namedtype.NamedType('expandedKey', univ.OctetString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(2400, 2400)))
        )))
    )


class ML_KEM_1024_PrivateKey(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('seed', univ.OctetString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(64, 64)).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('expandedKey', univ.OctetString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(3168, 3168))),
        namedtype.NamedType('both', univ.Sequence(componentType=namedtype.NamedTypes(
            namedtype.NamedType('seed', univ.OctetString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(64, 64))),
            namedtype.NamedType('expandedKey', univ.OctetString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(3168, 3168)))
        )))
    )


#  ML-KEM Algorithm Public Keys

class ML_KEM_512_PublicKey(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(800, 800)


class ML_KEM_768_PublicKey(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(1184, 1184)


class ML_KEM_1024_PublicKey(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(1568, 1568)


pk_ml_kem_512 = SubjectPublicKeyInfo()
pk_ml_kem_512['algorithm']['algorithm'] = id_alg_ml_kem_512
# pk_ml_kem_512['algorithm']['parameters'] are absent
# pk_ml_kem_512['subjectPublicKey'] = univ.BitString.fromOctetString(public_key)


pk_ml_kem_768 = SubjectPublicKeyInfo()
pk_ml_kem_768['algorithm']['algorithm'] = id_alg_ml_kem_768
# pk_ml_kem_768['algorithm']['parameters'] are absent
# pk_ml_kem_768['subjectPublicKey'] = univ.BitString.fromOctetString(public_key)


pk_ml_kem_1024 = SubjectPublicKeyInfo()
pk_ml_kem_1024['algorithm']['algorithm'] = id_alg_ml_kem_1024
# pk_ml_kem_1024['algorithm']['parameters'] are absent
# pk_ml_kem_1024['subjectPublicKey'] = univ.BitString.fromOctetString(public_key)


# No need to update the Algorithm Identifier map or the S/MIME
# Capabilities map because the parameters are always absent.
