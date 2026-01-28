#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley with assistance from asn1ate v.0.6.0.
#
# Copyright (c) 2024-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# RPKI Route Origin Authorizations (ROAs)
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9582.txt
#

from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import opentypemap

cmsContentTypesMap = opentypemap.get('cmsContentTypesMap')

MAX = float('inf')


id_ct_routeOriginAuthz = univ.ObjectIdentifier('1.2.840.113549.1.9.16.1.24')

afi_IPv4 = univ.OctetString(hexValue='0001').subtype(
               subtypeSpec=constraint.ValueSizeConstraint(2, 2))

afi_IPv6 = univ.OctetString(hexValue='0002').subtype(
               subtypeSpec=constraint.ValueSizeConstraint(2, 2))

ub_IPv4 = univ.Integer(32)

ub_IPv6 = univ.Integer(128)


class ASID(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, 4294967295)


class ROAIPAddress(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('address', univ.BitString()),
        # For IPv4, the maximum size of the BitString is ub_IPv4 bits
        # For IPv6, the maximum size of the BitString is ub_IPv6 bits
        namedtype.OptionalNamedType('maxLength', univ.Integer())
        # For IPv4, the maximum value of the Integer is ub_IPv4
        # For IPv6, the maximum value of the Integer is ub_IPv6
    )


class ROAAddresses(univ.SequenceOf):
    componentType = ROAIPAddress()
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


ROAIPAddressIPv4 = ROAIPAddress

ROAIPAddressIPv6 = ROAIPAddress

ROAAddressesIPv4 = ROAAddresses

ROAAddressesIPv6 = ROAAddresses


class ROAIPAddressFamily(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('addressFamily',
            univ.OctetString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(2, 2))),
        namedtype.NamedType('addresses', ROAAddresses())
    )


class RouteOriginAttestation(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('version',
            univ.Integer().subtype(explicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 0)).subtype(value=0)),
        namedtype.NamedType('asID', ASID()),
        namedtype.NamedType('ipAddrBlocks',
            univ.SequenceOf(componentType=ROAIPAddressFamily()).subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, 2)))
    )


addressFamilyIPv4 = ROAIPAddressFamily()
addressFamilyIPv4['addressFamily'] = afi_IPv4
addressFamilyIPv4['addresses'] = ROAAddressesIPv4()


addressFamilyIPv6 = ROAIPAddressFamily()
addressFamilyIPv6['addressFamily'] = afi_IPv6
addressFamilyIPv6['addresses'] = ROAAddressesIPv6()


# Update the CMS Content Types Map

_cmsContentTypesMapUpdate = {
    id_ct_routeOriginAuthz: RouteOriginAttestation(),
}

cmsContentTypesMap.update(_cmsContentTypesMapUpdate)
