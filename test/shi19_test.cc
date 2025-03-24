#include "crypto/shi19.h"

#include <gtest/gtest.h>
#include <iostream>
#include <string>
#include <vector>

#include <curve/params.h>

using namespace crypto;

TEST(Shi19Test, RandomizeTets) {
    CurveParams curve;
    std::vector<std::string> U = {"A", "B", "C"};
    std::vector<std::vector<std::string>> access_structure = {
        {"A", "B"},
        {"A", "C"},
        {"A", "B", "C"}
    };
    std::vector<std::string> attrs = {"A", "B"};
    crypto::shi19 scheme(curve.sm9_param, U);
    crypto::shi19::secretkey sk;
    scheme.shi19Keygen(attrs, &sk);
    crypto::shi19::plaintext ptx;
    scheme.RandomEncaps(&ptx);
    crypto::shi19::abe_ciphertext ctx;
    scheme.shi19Encrypt(ptx, access_structure, &ctx);
    crypto::shi19::plaintext res;
    scheme.shi19Decrypt(&ctx, attrs, &sk, &res);
    EXPECT_TRUE(!element_cmp(res.message, ptx.message));
}

int main() {
    ::testing::InitGoogleTest();
    return RUN_ALL_TESTS();
}