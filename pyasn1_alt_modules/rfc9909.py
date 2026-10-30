# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley
#
# Copyright (c) 2025-2026, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# SLH-DSA Signature Algorithm for X.509 Certificates
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9909.txt

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc9814


# Import definitions for pure mode of SLH-DSA from rfc9814

nistAlgorithms = rfc9814.nistAlgorithms

sigAlgs = rfc9814.sigAlgs

id_slh_dsa_sha2_128s = rfc9814.id_slh_dsa_sha2_128s

id_slh_dsa_sha2_128f = rfc9814.id_slh_dsa_sha2_128f

id_slh_dsa_sha2_192s = rfc9814.id_slh_dsa_sha2_192s

id_slh_dsa_sha2_192f = rfc9814.id_slh_dsa_sha2_192f

id_slh_dsa_sha2_256s = rfc9814.id_slh_dsa_sha2_256s

id_slh_dsa_sha2_256f = rfc9814.id_slh_dsa_sha2_256f

id_slh_dsa_shake_128s = rfc9814.id_slh_dsa_shake_128s

id_slh_dsa_shake_128f = rfc9814.id_slh_dsa_shake_128f

id_slh_dsa_shake_192s = rfc9814.id_slh_dsa_shake_192s

id_slh_dsa_shake_192f = rfc9814.id_slh_dsa_shake_192f

id_slh_dsa_shake_256s = rfc9814.id_slh_dsa_shake_256s

id_slh_dsa_shake_256s = rfc9814.id_slh_dsa_shake_256s

sa_slh_dsa_sha2_128s = rfc9814.sa_slh_dsa_sha2_128s

sa_slh_dsa_sha2_128f = rfc9814.sa_slh_dsa_sha2_128f

sa_slh_dsa_sha2_192s = rfc9814.sa_slh_dsa_sha2_192s

sa_slh_dsa_sha2_192f = rfc9814.sa_slh_dsa_sha2_192f

sa_slh_dsa_sha2_256s = rfc9814.sa_slh_dsa_sha2_256s

sa_slh_dsa_sha2_256f = rfc9814.sa_slh_dsa_sha2_256f

sa_slh_dsa_shake_128s = rfc9814.sa_slh_dsa_shake_128s

sa_slh_dsa_shake_128f = rfc9814.sa_slh_dsa_shake_128f

sa_slh_dsa_shake_192s = rfc9814.sa_slh_dsa_shake_192s

sa_slh_dsa_shake_192f = rfc9814.sa_slh_dsa_shake_192f

sa_slh_dsa_shake_256s = rfc9814.sa_slh_dsa_shake_256s

sa_slh_dsa_shake_256f = rfc9814.sa_slh_dsa_shake_256f

pk_slh_dsa_sha2_128s = rfc9814.pk_slh_dsa_sha2_128s

pk_slh_dsa_sha2_128f = rfc9814.pk_slh_dsa_sha2_128f

pk_slh_dsa_sha2_192s = rfc9814.pk_slh_dsa_sha2_192s

pk_slh_dsa_sha2_192f = rfc9814.pk_slh_dsa_sha2_192f

pk_slh_dsa_sha2_256s = rfc9814.pk_slh_dsa_sha2_256s

pk_slh_dsa_sha2_256f = rfc9814.pk_slh_dsa_sha2_256f

pk_slh_dsa_shake_128s = rfc9814.pk_slh_dsa_shake_128s

pk_slh_dsa_shake_128f = rfc9814.pk_slh_dsa_shake_128f

pk_slh_dsa_shake_192s = rfc9814.pk_slh_dsa_shake_192s

pk_slh_dsa_shake_192f = rfc9814.pk_slh_dsa_shake_192f

pk_slh_dsa_shake_256s = rfc9814.pk_slh_dsa_shake_256s

pk_slh_dsa_shake_256f = rfc9814.pk_slh_dsa_shake_256f

SLH_DSA_PrivateKey = rfc9814.SLH_DSA_PrivateKey

SLH_DSA_PublicKey = rfc9814.SLH_DSA_PublicKey


# Object Identifier definitions for pre-hash mode of SLH-DSA

id_hash_slh_dsa_sha2_128s_with_sha256 = sigAlgs + (35, )	

id_hash_slh_dsa_sha2_128f_with_sha256 = sigAlgs + (36, )	
		 		
id_hash_slh_dsa_sha2_192s_with_sha512 = sigAlgs + (37, )	
		 		
id_hash_slh_dsa_sha2_192f_with_sha512 = sigAlgs + (38, )	
		 		
id_hash_slh_dsa_sha2_256s_with_sha512 = sigAlgs + (39, )	
		 		
id_hash_slh_dsa_sha2_256f_with_sha512 = sigAlgs + (40, )	
		 		
id_hash_slh_dsa_shake_128s_with_shake128 = sigAlgs + (41, )	
		 		
id_hash_slh_dsa_shake_128f_with_shake128 = sigAlgs + (42, )	
		 		
id_hash_slh_dsa_shake_192s_with_shake256 = sigAlgs + (43, )	
		 		
id_hash_slh_dsa_shake_192f_with_shake256 = sigAlgs + (44, )	
		 		
id_hash_slh_dsa_shake_256s_with_shake256 = sigAlgs + (45, )	

id_hash_slh_dsa_shake_256f_with_shake256 = sigAlgs + (46, )	


# Signature algorithm definitions for pre-hash mode of SLH-DSA

sa_hash_slh_dsa_sha2_128s_with_sha256 = rfc5280.AlgorithmIdentifier()
sa_hash_slh_dsa_sha2_128s_with_sha256['algorithm'] = id_hash_slh_dsa_sha2_128s_with_sha256	
# sa_hash_slh_dsa_sha2_128s_with_sha256['parameters'] is always absent

sa_hash_slh_dsa_sha2_128f_with_sha256 = rfc5280.AlgorithmIdentifier()
sa_hash_slh_dsa_sha2_128f_with_sha256['algorithm'] = id_hash_slh_dsa_sha2_128f_with_sha256	
# sa_hash_slh_dsa_sha2_128f_with_sha256['parameters'] is always absent

sa_hash_slh_dsa_sha2_192s_with_sha512 = rfc5280.AlgorithmIdentifier()
sa_hash_slh_dsa_sha2_192s_with_sha512['algorithm'] = id_hash_slh_dsa_sha2_192s_with_sha512	
# sa_hash_slh_dsa_sha2_192s_with_sha512['parameters'] is always absent

sa_hash_slh_dsa_sha2_192f_with_sha512 = rfc5280.AlgorithmIdentifier()
sa_hash_slh_dsa_sha2_192f_with_sha512['algorithm'] = id_hash_slh_dsa_sha2_192f_with_sha512	
# sa_hash_slh_dsa_sha2_192f_with_sha512['parameters'] is always absent

sa_hash_slh_dsa_sha2_256s_with_sha512 = rfc5280.AlgorithmIdentifier()
sa_hash_slh_dsa_sha2_256s_with_sha512['algorithm'] = id_hash_slh_dsa_sha2_256s_with_sha512	
# sa_hash_slh_dsa_sha2_256s_with_sha512['parameters'] is always absent

sa_hash_slh_dsa_sha2_256f_with_sha512 = rfc5280.AlgorithmIdentifier()
sa_hash_slh_dsa_sha2_256f_with_sha512['algorithm'] = id_hash_slh_dsa_sha2_256f_with_sha512	
# sa_hash_slh_dsa_sha2_256f_with_sha512['parameters'] is always absent

sa_hash_slh_dsa_shake_128s_with_shake128 = rfc5280.AlgorithmIdentifier()
sa_hash_slh_dsa_shake_128s_with_shake128['algorithm'] = id_hash_slh_dsa_shake_128s_with_shake128	
# sa_hash_slh_dsa_shake_128s_with_shake128['parameters'] is always absent

sa_hash_slh_dsa_shake_128f_with_shake128 = rfc5280.AlgorithmIdentifier()
sa_hash_slh_dsa_shake_128f_with_shake128['algorithm'] = id_hash_slh_dsa_shake_128f_with_shake128	
# sa_hash_slh_dsa_shake_128f_with_shake128['parameters'] is always absent

sa_hash_slh_dsa_shake_192s_with_shake256 = rfc5280.AlgorithmIdentifier()
sa_hash_slh_dsa_shake_192s_with_shake256['algorithm'] = id_hash_slh_dsa_shake_192s_with_shake256	
# sa_hash_slh_dsa_shake_192s_with_shake256['parameters'] is always absent

sa_hash_slh_dsa_shake_192f_with_shake256 = rfc5280.AlgorithmIdentifier()
sa_hash_slh_dsa_shake_192f_with_shake256['algorithm'] = id_hash_slh_dsa_shake_192f_with_shake256	
# sa_hash_slh_dsa_shake_192f_with_shake256['parameters'] is always absent

sa_hash_slh_dsa_shake_256s_with_shake256 = rfc5280.AlgorithmIdentifier()
sa_hash_slh_dsa_shake_256s_with_shake256['algorithm'] = id_hash_slh_dsa_shake_256s_with_shake256	
# sa_hash_slh_dsa_shake_256s_with_shake256['parameters'] is always absent

sa_hash_slh_dsa_shake_256f_with_shake256 = rfc5280.AlgorithmIdentifier()
sa_hash_slh_dsa_shake_256f_with_shake256['algorithm'] = id_hash_slh_dsa_shake_256f_with_shake256
# sa_hash_slh_dsa_shake_256f_with_shake256['parameters'] is always absent


# Public key definitions for pre-hash mode of SLH-DSA

pk_hash_slh_dsa_sha2_128s_with_sha256 = rfc5280.SubjectPublicKeyInfo()
pk_hash_slh_dsa_sha2_128s_with_sha256['algorithm'] = sa_hash_slh_dsa_sha2_128s_with_sha256
# pk_hash_slh_dsa_sha2_128s_with_sha256['subjectPublicKey'] is the raw public key

pk_hash_slh_dsa_sha2_128f_with_sha256 = rfc5280.SubjectPublicKeyInfo()
pk_hash_slh_dsa_sha2_128f_with_sha256['algorithm'] = sa_hash_slh_dsa_sha2_128f_with_sha256
# pk_hash_slh_dsa_sha2_128f_with_sha256['subjectPublicKey'] is the raw public key

pk_hash_slh_dsa_sha2_192s_with_sha512 = rfc5280.SubjectPublicKeyInfo()
pk_hash_slh_dsa_sha2_192s_with_sha512['algorithm'] = sa_hash_slh_dsa_sha2_192s_with_sha512
# pk_hash_slh_dsa_sha2_192s_with_sha512['subjectPublicKey'] is the raw public key

pk_hash_slh_dsa_sha2_192f_with_sha512 = rfc5280.SubjectPublicKeyInfo()
pk_hash_slh_dsa_sha2_192f_with_sha512['algorithm'] = sa_hash_slh_dsa_sha2_192f_with_sha512
# pk_hash_slh_dsa_sha2_192f_with_sha512['subjectPublicKey'] is the raw public key

pk_hash_slh_dsa_sha2_256s_with_sha512 = rfc5280.SubjectPublicKeyInfo()
pk_hash_slh_dsa_sha2_256s_with_sha512['algorithm'] = sa_hash_slh_dsa_sha2_256s_with_sha512
# pk_hash_slh_dsa_sha2_256s_with_sha512['subjectPublicKey'] is the raw public key

pk_hash_slh_dsa_sha2_256f_with_sha512 = rfc5280.SubjectPublicKeyInfo()
pk_hash_slh_dsa_sha2_256f_with_sha512['algorithm'] = sa_hash_slh_dsa_sha2_256f_with_sha512
# pk_hash_slh_dsa_sha2_256f_with_sha512['subjectPublicKey'] is the raw public key

pk_hash_slh_dsa_shake_128s_with_shake128 = rfc5280.SubjectPublicKeyInfo()
pk_hash_slh_dsa_shake_128s_with_shake128['algorithm'] = sa_hash_slh_dsa_shake_128s_with_shake128	
# pk_hash_slh_dsa_shake_128s_with_shake128['subjectPublicKey'] is the raw public key

pk_hash_slh_dsa_shake_128f_with_shake128 = rfc5280.SubjectPublicKeyInfo()
pk_hash_slh_dsa_shake_128f_with_shake128['algorithm'] = sa_hash_slh_dsa_shake_128f_with_shake128	
# pk_hash_slh_dsa_shake_128f_with_shake128['subjectPublicKey'] is the raw public key

pk_hash_slh_dsa_shake_192s_with_shake256 = rfc5280.SubjectPublicKeyInfo()
pk_hash_slh_dsa_shake_192s_with_shake256['algorithm'] = sa_hash_slh_dsa_shake_192s_with_shake256
# pk_hash_slh_dsa_shake_192s_with_shake256['subjectPublicKey'] is the raw public key

pk_hash_slh_dsa_shake_192f_with_shake256 = rfc5280.SubjectPublicKeyInfo()
pk_hash_slh_dsa_shake_192f_with_shake256['algorithm'] = sa_hash_slh_dsa_shake_192f_with_shake256
# pk_hash_slh_dsa_shake_192f_with_shake256['subjectPublicKey'] is the raw public key

pk_hash_slh_dsa_shake_256s_with_shake256 = rfc5280.SubjectPublicKeyInfo()
pk_hash_slh_dsa_shake_256s_with_shake256['algorithm'] = sa_hash_slh_dsa_shake_256s_with_shake256
# pk_hash_slh_dsa_shake_256s_with_shake256['subjectPublicKey'] is the raw public key

pk_hash_slh_dsa_shake_256f_with_shake256 = rfc5280.SubjectPublicKeyInfo()
pk_hash_slh_dsa_shake_256f_with_shake256['algorithm'] = sa_hash_slh_dsa_shake_256f_with_shake256
# pk_hash_slh_dsa_shake_256f_with_shake256['subjectPublicKey'] is the raw public key
