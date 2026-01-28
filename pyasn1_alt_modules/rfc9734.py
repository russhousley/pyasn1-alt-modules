#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2025-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# X.509 Certificate Extended Key Usage for Instant Messaging URIs
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9734.txt
#

from pyasn1.type import univ


id_kp = univ.ObjectIdentifier('1.3.6.1.5.5.7.3')

id_kp_imUri = id_kp + (40,)
