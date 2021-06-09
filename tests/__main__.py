#
# This file is part of pyasn1-alt-modules software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# Copyright (c) 2021, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import unittest

suite = unittest.TestLoader().loadTestsFromNames(
    ['tests.test_pem.suite',
     'tests.test_rfc2040.suite',
     'tests.test_rfc2314.suite',
     'tests.test_rfc2315.suite',
     'tests.test_rfc2437.suite',
     'tests.test_rfc2459.suite',
     'tests.test_rfc2511.suite',
     'tests.test_rfc2528.suite',
     'tests.test_rfc2560.suite',
     'tests.test_rfc2631.suite',
     'tests.test_rfc2634.suite',
     'tests.test_rfc2876.suite',
     'tests.test_rfc2985.suite',
     'tests.test_rfc2986.suite',
     'tests.test_rfc3058.suite',
     'tests.test_rfc3114.suite',
     'tests.test_rfc3125.suite',
     'tests.test_rfc3161.suite',
     'tests.test_rfc3217.suite',
     'tests.test_rfc3274.suite',
     'tests.test_rfc3279.suite',
     'tests.test_rfc3280.suite',
     'tests.test_rfc3281.suite',
     'tests.test_rfc3370.suite',
     'tests.test_rfc3447.suite',
     'tests.test_rfc3537.suite',
     'tests.test_rfc3560.suite',
     'tests.test_rfc3565.suite',
     'tests.test_rfc3657.suite',
     'tests.test_rfc3709.suite',
     'tests.test_rfc3739.suite',
     'tests.test_rfc3770.suite',
     'tests.test_rfc3779.suite',
     'tests.test_rfc3820.suite',
     'tests.test_rfc3852.suite',
     'tests.test_rfc3874.suite',
     'tests.test_rfc4010.suite',
     'tests.test_rfc4043.suite',
     'tests.test_rfc4055.suite',
     'tests.test_rfc4056.suite',
     'tests.test_rfc4059.suite',
     'tests.test_rfc4073.suite',
     'tests.test_rfc4108.suite',
     'tests.test_rfc4210.suite',
     'tests.test_rfc4211.suite',
     'tests.test_rfc4231.suite',
     'tests.test_rfc4262.suite',
     'tests.test_rfc4334.suite',
     'tests.test_rfc4357.suite',
     'tests.test_rfc4387.suite',
     'tests.test_rfc4476.suite',
     'tests.test_rfc4490.suite',
     'tests.test_rfc4491.suite',
     'tests.test_rfc4683.suite',
     'tests.test_rfc4985.suite',
     'tests.test_rfc4998.suite',
     'tests.test_rfc5035.suite',
     'tests.test_rfc5055.suite',
     'tests.test_rfc5083.suite',
     'tests.test_rfc5084.suite',
     'tests.test_rfc5126.suite',
     'tests.test_rfc5208.suite',
     'tests.test_rfc5275.suite',
     'tests.test_rfc5276.suite',
     'tests.test_rfc5280.suite',
     'tests.test_rfc5480.suite',
     'tests.test_rfc5544.suite',
     'tests.test_rfc5636.suite',
     'tests.test_rfc5639.suite',
     'tests.test_rfc5649.suite',
     'tests.test_rfc5652.suite',
     'tests.test_rfc5697.suite',
     'tests.test_rfc5751.suite',
     'tests.test_rfc5752.suite',
     'tests.test_rfc5753.suite',
     'tests.test_rfc5755.suite',
     'tests.test_rfc5913.suite',
     'tests.test_rfc5914.suite',
     'tests.test_rfc5915.suite',
     'tests.test_rfc5916.suite',
     'tests.test_rfc5917.suite',
     'tests.test_rfc5924.suite',
     'tests.test_rfc5934.suite',
     'tests.test_rfc5940.suite',
     'tests.test_rfc5958.suite',
     'tests.test_rfc5990.suite',
     'tests.test_rfc6010.suite',
     'tests.test_rfc6019.suite',
     'tests.test_rfc6031.suite',
     'tests.test_rfc6032.suite',
     'tests.test_rfc6066.suite',
     'tests.test_rfc6120.suite',
     'tests.test_rfc6187.suite',
     'tests.test_rfc6210.suite',
     'tests.test_rfc6211.suite',
     'tests.test_rfc6482.suite',
     'tests.test_rfc6484.suite',
     'tests.test_rfc6486.suite',
     'tests.test_rfc6487.suite',
     'tests.test_rfc6494.suite',
     'tests.test_rfc6664.suite',
     'tests.test_rfc6955.suite',
     'tests.test_rfc6960.suite',
     'tests.test_rfc6962.suite',
     'tests.test_rfc7030.suite',
     'tests.test_rfc7191.suite',
     'tests.test_rfc7229.suite',
     'tests.test_rfc7292.suite',
     'tests.test_rfc7296.suite',
     'tests.test_rfc7508.suite',
     'tests.test_rfc7585.suite',
     'tests.test_rfc7633.suite',
     'tests.test_rfc7693.suite',
     'tests.test_rfc7773.suite',
     'tests.test_rfc7836.suite',
     'tests.test_rfc7894.suite',
     'tests.test_rfc7906.suite',
     'tests.test_rfc7914.suite',
     'tests.test_rfc8017.suite',
     'tests.test_rfc8018.suite',
     'tests.test_rfc8103.suite',
     'tests.test_rfc8209.suite',
     'tests.test_rfc8226.suite',
     'tests.test_rfc8358.suite',
     'tests.test_rfc8360.suite',
     'tests.test_rfc8398.suite',
     'tests.test_rfc8410.suite',
     'tests.test_rfc8418.suite',
     'tests.test_rfc8419.suite',
     'tests.test_rfc8479.suite',
     'tests.test_rfc8494.suite',
     'tests.test_rfc8520.suite',
     'tests.test_rfc8619.suite',
     'tests.test_rfc8649.suite',
     'tests.test_rfc8692.suite',
     'tests.test_rfc8696.suite',
     'tests.test_rfc8702.suite',
     'tests.test_rfc8708.suite',
     'tests.test_rfc8769.suite',
     'tests.test_rfc8894.suite',
     'tests.test_rfc8951.suite',
     'tests.test_rfc8994.suite',
     'tests.test_rfc8995.suite',
     'tests.test_rfc9044.suite']
)


if __name__ == '__main__':
    import sys

    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
