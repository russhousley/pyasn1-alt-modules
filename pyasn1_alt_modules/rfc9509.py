#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2024-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Extended Key Usage (EKU) for 5G Network Functions
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9509.txt
#

from pyasn1.type import univ


id_kp = univ.ObjectIdentifier('1.3.6.1.5.5.7.3')

id_kp_jwt = id_kp + (37,)

id_kp_httpContentEncrypt = id_kp + (38,)

id_kp_oauthAccessTokenSigning = id_kp + (39,)
