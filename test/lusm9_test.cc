#include "crypto/lusm9.h"
#include <gtest/gtest.h>
#include <vector>
#include <iostream>

#include <curve/params.h>

using namespace crypto;

TEST(lusm9Test, RandomizeTest) {
    CurveParams curve;
    std::vector<std::string> attrs = {"A", "B", "C"};
    std::string policy = "A and B and C";
    crypto::lusm9 scheme(curve.sm9_param);
    crypto::lusm9::attribute_set A;
    A.attrs = attrs;
    crypto::lusm9::secretkey sk;
    scheme.Keygen(&A, &sk);
    crypto::lusm9::plaintext ptx; // wild ptr!!!
    // scheme.Encaps(42, &ptx);
    scheme.RandomEncaps(&ptx);
    crypto::lusm9::ciphertext ctx;
    scheme.Encrypt(ptx, policy, &ctx);
    crypto::lusm9::plaintext res;
    scheme.Decrypt(&ctx, &A, &sk, &res);
    EXPECT_TRUE(!element_cmp(res.message, ptx.message));
}

int main() {
    ::testing::InitGoogleTest();
    return RUN_ALL_TESTS();
}