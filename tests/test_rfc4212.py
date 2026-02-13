#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley
# Copyright (c) 2025-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc4211
from pyasn1_alt_modules import rfc4212


class OpenPGPCertTemplateTestCase(unittest.TestCase):
    pem_text = """\
MIIEiwIBMDAAMIIEgjCCBH4GCSsGAQUFBwUBBzCCBG8GCisGAQUFBwUBBwIwggRf
BIIEW5kBogQ8WCeiEQDj+53/////////////////////////////////////////
////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////8r7wCg
/37///////////////////+6cQP/aLz/////////////////////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
//9WcQP+OB//////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
///////////////////////////////////////////////yY7QZQWz/////////
/////////////////20+iQBJBBARAgAJBQI8WCeiAhsDAAoJEENc////BndawgCg
6wD///////////////////8bdQCg9OT///////////////////+oPbkCDQQ8WCei
EAgA9kL/////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
/////////////////////ws7AAICB/43uv//////////////////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////3yGJAEkEGBECAAkF
AjxYJ6ICGwwACgkQQ1z///8Gd8feAJ4hM////////////////////zkbAJ9k1///
/////////////////2MI
"""

    def setUp(self):
        self.asn1Spec = rfc4211.CertRequest()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual(48, asn1Object['certReqId'])

        found = False

        for ctrl in asn1Object['controls']:
            if ctrl['type'] == rfc4212.id_regCtrl_altCertTemplate:
                act, rest = der_decoder(ctrl['value'],
                    asn1Spec=rfc4212.AttributeTypeAndValue())
                self.assertFalse(rest)
                self.assertTrue(act.prettyPrint())
                self.assertEqual(ctrl['value'], der_encoder(act))

                self.assertEqual(rfc4212.id_openPGPCertTemplateExt, act['type'])
                opgpcte, rest = der_decoder(act['value'],
                    asn1Spec=rfc4212.OpenPGPCertTemplateExtended())
                self.assertFalse(rest)
                self.assertTrue(opgpcte.prettyPrint())
                self.assertEqual(act['value'], der_encoder(opgpcte))
                
                self.assertTrue(opgpcte.hasValue())
                found = True

        self.assertTrue(found)

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate,
            asn1Spec=self.asn1Spec, decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual(48, asn1Object['certReqId'])
        
        found = False

        for ctrl in asn1Object['controls']:
            if ctrl['type'] == rfc4212.id_regCtrl_altCertTemplate:
                self.assertEqual(rfc4212.id_openPGPCertTemplateExt,
                    ctrl['value']['type'])
                self.assertTrue(ctrl['value']['value'].hasValue())
                found = True

        self.assertTrue(found)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
