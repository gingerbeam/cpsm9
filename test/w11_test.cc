#include "crypto/w11.h"
#include <gtest/gtest.h>
#include <vector>
#include <iostream>

#include <curve/params.h>

using namespace crypto;

TEST(Waters11Test, RandomizeTest) {
    CurveParams curve;
    std::vector<std::string> attrs = {"A", "B", "C"};
    std::string policy = "A and B and C";
    // crypto::w11 scheme(curve.sm9_param, attrs);
    crypto::w11 scheme(curve.a_param, attrs);
    crypto::w11::attribute_set A;
    A.attrs = attrs;
    crypto::w11::secretkey sk;
    scheme.Keygen(&A, &sk);
    crypto::w11::plaintext ptx; // wild ptr!!!
    // scheme.Encaps(42, &ptx);
    scheme.RandomEncaps(&ptx);
    crypto::w11::ciphertext ctx;
    scheme.Encrypt(ptx, policy, &ctx);
    crypto::w11::plaintext res;
    scheme.Decrypt(&ctx, &A, &sk, &res);
    EXPECT_TRUE(!element_cmp(res.message, ptx.message));
    // if (!element_cmp(res.message, ptx.message)) {
    //     printf("Decryption successful\n");
    // } else {
    //     printf("Decryption failed\n");
    // }
}

int main() {
    ::testing::InitGoogleTest();
    return RUN_ALL_TESTS();
}