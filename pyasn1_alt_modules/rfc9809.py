#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2025-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# X.509 Certificate Extended Key Usage (EKU) for configuration, updates and
#    safety communication
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9809.txt
#

from pyasn1_alt_modules import rfc5280


id_kp = rfc5280.id_kp

id_kp_configSigning = id_kp + (41,)

id_kp_trustAnchorConfigSigning = id_kp + (42,)

id_kp_updatePackageSigning = id_kp + (43,)

id_kp_safetyCommunication = id_kp + (44,)
