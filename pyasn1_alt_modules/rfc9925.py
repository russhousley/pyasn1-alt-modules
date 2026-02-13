# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Unsigned X.509 Certificates
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9925.txt

from pyasn1.type import char
from pyasn1.type import constraint
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import opentypemap

certificateAttributesMap = opentypemap.get('certificateAttributesMap')


# Signature

class EmptyUTF8String(char.UTF8String):
    subtypeSpec = constraint.ValueSizeConstraint(0, 0)


id_alg_unsigned = univ.ObjectIdentifier('1.3.6.1.5.5.7.6.36')


sa_unsigned = rfc5280.AlgorithmIdentifier()
sa_unsigned['algorithm'] = id_alg_unsigned
# sa_unsigned['parameters'] is always absent


# Issuer

id_rdna_unsigned = univ.ObjectIdentifier('1.3.6.1.5.5.7.25.1')


at_unsigned = rfc5280.Attribute()
at_unsigned['type'] = id_rdna_unsigned
at_unsigned['values'][0] = char.UTF8String('')


# Update the certificateAttributesMap

_certificateAttributesMapUpdate = {
    id_rdna_unsigned: EmptyUTF8String(),
}

certificateAttributesMap.update(_certificateAttributesMapUpdate)