# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley
#
# Copyright (c) 2025-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# ML-DSA Signature Algorithm for the CMS
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9882.txt

from pyasn1_alt_modules import rfc9881


# Object Identifiers

nistAlgorithms = rfc9881.nistAlgorithms

sigAlgs = rfc9881.sigAlgs

id_ml_dsa_44 = rfc9881.id_ml_dsa_44

id_ml_dsa_65 = rfc9881.id_ml_dsa_65

id_ml_dsa_87 = rfc9881.id_ml_dsa_87


# Signature Algorithm Identifier

sa_ml_dsa_44 = rfc9881.sa_ml_dsa_44

sa_ml_dsa_65 = rfc9881.sa_ml_dsa_65

sa_ml_dsa_87 = rfc9881.sa_ml_dsa_87


# No need to add the id_ml_dsa_* object identifiers to the
# algorithmIdentifierMap or the smimeCapabilityMap because the
# parameters are always absent.
