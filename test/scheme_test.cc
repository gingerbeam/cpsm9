#include "crypto/w11.h"
#include "crypto/rw13.h"
#include "crypto/susm9.h"
#include "crypto/lusm9.h"
#include <gtest/gtest.h>
#include <vector>
#include <iostream>

#include <curve/params.h>

using namespace crypto;

TEST(Waters11Test, RandomizeTest) {
    CurveParams curve;
    std::vector<std::string> attrs = {"A", "B", "C"};
    std::string policy = "A and B and C";
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
}

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
}

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