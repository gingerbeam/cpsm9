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
    ji21::public_parameter pub;
    ji21::master_secretkey msk;
    ji21::ji21_setup(&pub, &msk);
    std::vector<std::string> user_attrs = {"attrX", "attrY" };
    // std::vector<std::string> user_attrs = {"attr25", "attr6", "attr7s","attr1","attr7","attr8" };
    ji21::ji21Prv* prv = ji21::ji21_keygen(&pub, &msk, user_attrs);
    // std::string policy = "attr1 attr2 attr3 attr4 1of2 2of2 1of2 attr5 attr6 attr7 attr8 1of2 2of2 1of2 2of2";
    std::string policy = "attrX or (attrY and attrZ)";
    string M_string = "hello";
    element_t M;
    element_init_GT(M, pub.pairing);
    string_to_element(M, M_string);
    ji21::ji21Cph* cph = ji21::ji21_enc(&pub, policy, M);
    ji21::ji21ElementBoolean* result = ji21::ji21_dec(&pub, prv, cph);
    EXPECT_TRUE(result->b);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}