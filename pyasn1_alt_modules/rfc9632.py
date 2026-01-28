#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2021-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Digital Signatures on geofeed data
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9092.txt
# https://www.rfc-editor.org/rfc/rfc9632.txt
#

from pyasn1_alt_modules import rfc9092


# Imports from RFC 9092

id_ct = rfc9092.id_ct

id_ct_geofeedCSVwithCRLF = rfc9092.id_ct_geofeedCSVwithCRLF


# No need to update the CMS Content Type Map; the import of rfc9092 did it
