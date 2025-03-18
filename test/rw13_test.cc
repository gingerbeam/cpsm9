#include "crypto/rw13.h"
#include <gtest/gtest.h>
#include <vector>
#include <iostream>

#include <curve/params.h>

using namespace crypto;

TEST(RW13Test, RandomizeTest) {
    CurveParams curve;
    std::vector<std::string> attrs = {"A", "B", "C"};
    std::string policy = "A and B and C";
    // crypto::rw13 scheme(curve.sm9_param, attrs);
    crypto::rw13 scheme(curve.a_param);
    crypto::rw13::attribute_set A;
    A.attrs = attrs;
    crypto::rw13::secretkey sk;
    scheme.Keygen(&A, &sk);
    crypto::rw13::plaintext ptx; // wild ptr!!!
    // scheme.Encaps(42, &ptx);
    scheme.RandomEncaps(&ptx);
    crypto::rw13::ciphertext ctx;
    scheme.Encrypt(ptx, policy, &ctx);
    crypto::rw13::plaintext res;
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