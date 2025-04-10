#include "crypto/w11.h"
#include "crypto/rw13.h"
#include "crypto/susm9.h"
#include "crypto/lusm9.h"
#include "crypto/sm9.h"
#include "crypto/shi19.h"
#include "crypto/ji21.h"
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

TEST(Waters11Test, AsymmetricTest) {
    CurveParams curve;
    std::vector<std::string> attrs = {"A", "B", "C"};
    std::string policy = "A and B and C";
    crypto::w11 scheme(curve.sm9_param, attrs);
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

TEST(RW13Test, AsymmetricTest) {
    CurveParams curve;
    std::vector<std::string> attrs = {"A", "B", "C"};
    std::string policy = "A and B and C";
    // crypto::rw13 scheme(curve.sm9_param, attrs);
    crypto::rw13 scheme(curve.sm9_param);
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
    crypto::susm9 scheme(curve.a_param, attrs);
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

TEST(susm9Test, AsymmetricTest) {
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
    crypto::lusm9 scheme(curve.a_param);
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

TEST(lusm9Test, AsymmetricTest) {
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

TEST(sm9Tetst, RandomizeTest) {
    CurveParams curve;
    crypto::sm9 scheme(curve.a_param);
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

TEST(sm9Tetst, AsymmmetricTest) {
    CurveParams curve;
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

TEST(Shi19Test, RandomizeTest) {
    CurveParams curve;
    std::vector<std::string> U = {"A", "B", "C"};
    std::vector<std::vector<std::string>> access_structure = {
        {"A", "B"},
        {"A", "C"},
        {"A", "B", "C"}
    };
    std::vector<std::string> attrs = {"A", "B"};
    crypto::shi19 scheme(curve.a_param, U);
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

TEST(Shi19Test, AsymmetricTest) {
    CurveParams curve;
    std::vector<std::string> U = {"A", "B", "C"};
    std::vector<std::vector<std::string>> access_structure = {
        {"A", "B"},
        {"A", "C"},
        {"A", "B", "C"}
    };
    std::vector<std::string> attrs = {"A", "B"};
    crypto::shi19 scheme(curve.a_param, U);
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

TEST(ji21Test, RandomizeTest) {
    CurveParams curve;
    crypto::ji21 scheme(curve.a_param);
    std::vector<std::string> user_attrs = {"A", "B", "C"};
    ji21::ji21Prv* prv = scheme.ji21_keygen(user_attrs);
    std::string policy = "A and B and C";
    crypto::ji21::plaintext ptx; // wild ptr!!!
    // scheme.Encaps(42, &ptx);
    scheme.RandomEncaps(&ptx);
    ji21::ji21Cph* cph = scheme.ji21_enc(policy, &ptx);
    ji21::ji21ElementBoolean* result = scheme.ji21_dec(prv, cph);
    EXPECT_TRUE(result->b);
    EXPECT_TRUE(!element_cmp(result->e, ptx.message));
}

TEST(ji21Test, AsymmetricTest) {
    CurveParams curve;
    crypto::ji21 scheme(curve.sm9_param);
    std::vector<std::string> user_attrs = {"A", "B", "C"};
    ji21::ji21Prv* prv = scheme.ji21_keygen(user_attrs);
    std::string policy = "A and B and C";
    crypto::ji21::plaintext ptx; // wild ptr!!!
    // scheme.Encaps(42, &ptx);
    scheme.RandomEncaps(&ptx);
    ji21::ji21Cph* cph = scheme.ji21_enc(policy, &ptx);
    ji21::ji21ElementBoolean* result = scheme.ji21_dec(prv, cph);
    EXPECT_TRUE(result->b);
    EXPECT_TRUE(!element_cmp(result->e, ptx.message));
}

int main() {
    ::testing::InitGoogleTest();
    return RUN_ALL_TESTS();
}