#include "crypto/sm9.h"
#include <gtest/gtest.h>
#include <string>

#include <curve/params.h>

using namespace crypto;

TEST(sm9Tetst, RandomizeTest) {
    CurveParams curve;
    // crypto::sm9 scheme(42);
    // std::string id = "test";
    // scheme.simulate(curve.sm9_param, id);
    crypto::sm9 scheme(curve.sm9_param);
    crypto::sm9::secretkey sk;
    std::string id = "test";
    scheme.Keygen(id, &sk);
    crypto::sm9::plaintext ptx; // wild ptr!!!
    // scheme.Encaps(42, &ptx);
    scheme.RandomEncaps(&ptx);
    crypto::sm9::ciphertext ctx;
    scheme.Encrypt(ptx, id, &ctx);
    crypto::sm9::plaintext res;
    scheme.Decrypt(&ctx, &sk, &res);
    EXPECT_TRUE(!element_cmp(res.message, ptx.message));
}

int main() {
    ::testing::InitGoogleTest();
    return RUN_ALL_TESTS();
}