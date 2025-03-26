#include "crypto/ji21.h"
#include <gtest/gtest.h>
#include <algorithm>

#include <pbc/pbc.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstring>

#include <curve/params.h>

using namespace crypto;
using namespace std;

TEST(ji21Test, SimpleExpressionTest) {
    CurveParams curve;
    crypto::ji21 scheme(curve.sm9_param);
    std::vector<std::string> user_attrs = {"A", "B", "C"};
    ji21::ji21Prv* prv = scheme.ji21_keygen(user_attrs);
    std::string policy = "A and B and C";
    string M_string = "hello";
    crypto::ji21::plaintext ptx; // wild ptr!!!
    // scheme.Encaps(42, &ptx);
    scheme.RandomEncaps(&ptx);
    ji21::ji21Cph* cph = scheme.ji21_enc(policy, &ptx);
    ji21::ji21ElementBoolean* result = scheme.ji21_dec(prv, cph);
    EXPECT_TRUE(result->b);
    EXPECT_TRUE(!element_cmp(result->e, ptx.message));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}