#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2019-2023, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# X.509v3 Certificates for Secure Shell Authentication
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc6187.txt
#

from pyasn1.type import univ

id_pkix = univ.ObjectIdentifier('1.3.6.1.5.5.7')

id_kp = id_pkix + (3, )

id_kp_secureShellClient = id_kp + (21, )
id_kp_secureShellServer = id_kp + (22, )
