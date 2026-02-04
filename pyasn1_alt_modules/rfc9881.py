#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2025-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# ML-DSA Algorithm for use in X.509 Certificats
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9881.txt
# https://www.rfc-editor.org/errata/eid8699
#

from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import  tag
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280


# Imports from RFC 5280

AlgorithmIdentifier = rfc5280.AlgorithmIdentifier

SubjectPublicKeyInfo = rfc5280.SubjectPublicKeyInfo


# Object Identifiers

nistAlgorithms = univ.ObjectIdentifier('2.16.840.1.101.3.4')

sigAlgs = nistAlgorithms + (3, )

id_ml_dsa_44 = sigAlgs + (17, )

id_ml_dsa_65 = sigAlgs + (18, )

id_ml_dsa_87 = sigAlgs + (19, )


# ML-DSA Signature Algorithms

sa_ml_dsa_44 = AlgorithmIdentifier()
sa_ml_dsa_44['algorithm'] = id_ml_dsa_44
# sa_ml_dsa_44['parameters'] are absent

sa_ml_dsa_65 = AlgorithmIdentifier()
sa_ml_dsa_65['algorithm'] = id_ml_dsa_65
# sa_ml_dsa_65['parameters'] are absent

sa_ml_dsa_87 = AlgorithmIdentifier()
sa_ml_dsa_87['algorithm'] = id_ml_dsa_87
# sa_ml_dsa_87['parameters'] are absent


# Public Key for the ML-DSA algorithm 

pk_ml_dsa_44 = SubjectPublicKeyInfo()
pk_ml_dsa_44['algorithm']['algorithm'] = id_ml_dsa_44
# pk_ml_dsa_44['algorithm']['parameters'] are absent
# pk_ml_dsa_44['subjectPublicKey'] = univ.BitString.fromOctetString(public_key)

pk_ml_dsa_65 = SubjectPublicKeyInfo()
pk_ml_dsa_65['algorithm']['algorithm'] = id_ml_dsa_65
# pk_ml_dsa_65['algorithm']['parameters'] are absent
# pk_ml_dsa_65['subjectPublicKey'] = univ.BitString.fromOctetString(public_key)

pk_ml_dsa_87 = SubjectPublicKeyInfo()
pk_ml_dsa_87['algorithm']['algorithm'] = id_ml_dsa_87
# pk_ml_dsa_87['algorithm']['parameters'] are absent
# pk_ml_dsa_87['subjectPublicKey'] = univ.BitString.fromOctetString(public_key)


# Private key for the ML-DSA algorithm outside an asymmetric key package

class ML_DSA_44_PrivateKey(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('seed', univ.OctetString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(32, 32)).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('expandedKey', univ.OctetString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(2560, 2560))),
        namedtype.NamedType('both', univ.Sequence(componentType=namedtype.NamedTypes(
            namedtype.NamedType('seed', univ.OctetString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(32, 32))),
            namedtype.NamedType('expandedKey', univ.OctetString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(2560, 2560)))
        )))
    )


class ML_DSA_65_PrivateKey(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('seed', univ.OctetString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(32, 32)).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('expandedKey', univ.OctetString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(4032, 4032))),
        namedtype.NamedType('both', univ.Sequence(componentType=namedtype.NamedTypes(
            namedtype.NamedType('seed', univ.OctetString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(32, 32))),
            namedtype.NamedType('expandedKey', univ.OctetString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(4032, 4032)))
        )))
    )


class ML_DSA_87_PrivateKey(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('seed', univ.OctetString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(32, 32)).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('expandedKey', univ.OctetString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(4896, 4896))),
        namedtype.NamedType('both', univ.Sequence(componentType=namedtype.NamedTypes(
            namedtype.NamedType('seed', univ.OctetString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(32, 32))),
            namedtype.NamedType('expandedKey', univ.OctetString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(4896, 4896)))
        )))
    )


# Public key for the ML-DSA algorithm outside of a certificate

class ML_DSA_44_PublicKey(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(1312, 1312)


class ML_DSA_65_PublicKey(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(1952, 1952)


class ML_DSA_87_PublicKey(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(2592, 2592)


# No need to update the Algorithm Identifier map or the S/MIME
# Capabilities map because the parameters are always absent.
