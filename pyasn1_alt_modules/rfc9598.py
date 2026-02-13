#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2024-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Internationalized Email Addresses in X.509 Certificates
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9598.txt
#

from pyasn1.type import char
from pyasn1.type import constraint
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import opentypemap

otherNamesMap = opentypemap.get('otherNamesMap')

MAX = float('inf')


# SmtpUTF8Mailbox contains Mailbox as specified in Section 3.3 of RFC 6531.
# RFC 9598 requires that the domain name be represented as A-labels.

id_pkix = rfc5280.id_pkix

id_on = id_pkix + (8, )

id_on_SmtpUTF8Mailbox = id_on + (9, )


class SmtpUTF8Mailbox(char.UTF8String):
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


on_SmtpUTF8Mailbox = rfc5280.AnotherName()
on_SmtpUTF8Mailbox['type-id'] = id_on_SmtpUTF8Mailbox
on_SmtpUTF8Mailbox['value'] = SmtpUTF8Mailbox()


# Update the Other Names Map

_otherNamesMapUpdate = {
    id_on_SmtpUTF8Mailbox: SmtpUTF8Mailbox(),
}

otherNamesMap.update(_otherNamesMapUpdate)
