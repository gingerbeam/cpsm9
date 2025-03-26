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
    // std::vector<std::string> user_attrs = {"attr25", "attr6", "attr7s","attr1","attr7","attr8" };
    ji21::ji21Prv* prv = scheme.ji21_keygen(user_attrs);
    std::string policy = "A and B and C";
    // std::string policy = "attr1 attr2 attr3 attr4 1of2 2of2 1of2 attr5 attr6 attr7 attr8 1of2 2of2 1of2 2of2"; 
    string M_string = "hello";
    crypto::ji21::plaintext ptx; // wild ptr!!!
    // scheme.Encaps(42, &ptx);
    scheme.RandomEncaps(&ptx);
    ji21::ji21Cph* cph = scheme.ji21_enc(policy, &ptx);
    ji21::ji21ElementBoolean* result = scheme.ji21_dec(prv, cph);
    // ji21::print_policy_tree(cph->p, 0);
    EXPECT_TRUE(result->b);
    EXPECT_TRUE(!element_cmp(result->e, ptx.message));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}