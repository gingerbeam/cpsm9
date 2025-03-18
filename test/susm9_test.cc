#include "crypto/susm9.h"
#include <gtest/gtest.h>
#include <vector>
#include <iostream>

#include <curve/params.h>

using namespace crypto;

TEST(susm9Test, RandomizeTest) {
    CurveParams curve;
    std::vector<std::string> attrs = {"A", "B", "C"};
    std::string policy = "A and B and C";
    crypto::susm9 scheme(curve.sm9_param, attrs);
    crypto::susm9::attribute_set A;
    A.attrs = attrs;
    crypto::susm9::secretkey sk;
    scheme.Keygen(&A, &sk);
    crypto::susm9::plaintext ptx; // wild ptr!!!
    // scheme.Encaps(42, &ptx);
    scheme.RandomEncaps(&ptx);
    crypto::susm9::ciphertext ctx;
    scheme.Encrypt(ptx, policy, &ctx);
    crypto::susm9::plaintext res;
    scheme.Decrypt(&ctx, &A, &sk, &res);
    EXPECT_TRUE(!element_cmp(res.message, ptx.message));
}

int main() {
    ::testing::InitGoogleTest();
    return RUN_ALL_TESTS();
}