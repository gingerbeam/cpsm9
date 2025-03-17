#include "utils/lsss.h"
#include <gtest/gtest.h>
#include <algorithm>

#include <pbc/pbc.h>

#include <curve/params.h>

using namespace utils;

// CurveParams curve;

TEST(LSSSTest, SimpleExpressionTest) {
    CurveParams curve;
    pairing_t pairing;
    pbc_param_t par;
    pbc_param_init_set_str(par, curve.a_param.c_str());
    pairing_init_pbc_param(pairing, par);
    std::string policy = "(A and B and C) and (D or E or F) and (G and H and (I or J or K or L))";
    LSSS parser(&pairing, policy);
    std::cout << "DEBUG probe parser OK\n";
    element_t secret;
    element_init_Zr(secret, pairing);
    element_set_si(secret, 42);
    std::vector<element_t*> shares = parser.share(&secret);
    std::cout << "DEBUG probe share OK\n";
    element_t res_s;
    element_init_Zr(res_s, pairing);
    parser.reconstruct(std::vector<std::string>{"A", "B", "C", "D", "G", "H", "I"}, shares, &res_s);
    std::cout << "DEBUG probe reconstruct OK\n";
    EXPECT_TRUE(!element_cmp(secret, res_s));
}

// (A or B) and (C and D and (E or F)) and (G or H or (I and J))
// "A", "C", "D", "E", "G"
TEST(LSSSTest, ComplexExpressionTest) {
    CurveParams curve;
    pairing_t pairing;
    pbc_param_t par;
    pbc_param_init_set_str(par, curve.a_param.c_str());
    pairing_init_pbc_param(pairing, par);
    std::string policy = "(A or B) and (C and D and (E or F)) and (G or H or (I and J))";
    LSSS parser(&pairing, policy);
    std::cout << "DEBUG probe parser OK\n";
    element_t secret;
    element_init_Zr(secret, pairing);
    element_set_si(secret, 42);
    std::vector<element_t*> shares = parser.share(&secret);
    std::cout << "DEBUG probe share OK\n";
    element_t res_s;
    element_init_Zr(res_s, pairing);
    parser.reconstruct(std::vector<std::string>{"A", "C", "D", "E", "G"}, shares, &res_s);
    std::cout << "DEBUG probe reconstruct OK\n";
    EXPECT_TRUE(!element_cmp(secret, res_s));
}

// A or B and C and D and E or F and G or H or I and J
// "A", "C", "D"
TEST(LSSSTest, PriorityTest) {
    CurveParams curve;
    pairing_t pairing;
    pbc_param_t par;
    pbc_param_init_set_str(par, curve.a_param.c_str());
    pairing_init_pbc_param(pairing, par);
    std::string policy = "A or B and C and D and E or F and G or H or I and J";
    LSSS parser(&pairing, policy);
    std::cout << "DEBUG probe parser OK\n";
    element_t secret;
    element_init_Zr(secret, pairing);
    element_set_si(secret, 42);
    std::vector<element_t*> shares = parser.share(&secret);
    std::cout << "DEBUG probe share OK\n";
    element_t res_s;
    element_init_Zr(res_s, pairing);
    parser.reconstruct(std::vector<std::string>{"A", "C", "D"}, shares, &res_s);
    std::cout << "DEBUG probe reconstruct OK\n";
    EXPECT_TRUE(!element_cmp(secret, res_s));
}

// CP and ABE and (sm9 or pku)
// "ABE", "CP", "sm9"
TEST(LSSSTest, ArbitraryAttributeTest) {
    CurveParams curve;
    pairing_t pairing;
    pbc_param_t par;
    pbc_param_init_set_str(par, curve.a_param.c_str());
    pairing_init_pbc_param(pairing, par);
    std::string policy = "CP and ABE and (sm9 or pku)";
    LSSS parser(&pairing, policy);
    std::cout << "DEBUG probe parser OK\n";
    element_t secret;
    element_init_Zr(secret, pairing);
    element_set_si(secret, 42);
    std::vector<element_t*> shares = parser.share(&secret);
    std::cout << "DEBUG probe share OK\n";
    element_t res_s;
    element_init_Zr(res_s, pairing);
    parser.reconstruct(std::vector<std::string>{"ABE", "CP", "sm9"}, shares, &res_s);
    std::cout << "DEBUG probe reconstruct OK\n";
    EXPECT_TRUE(!element_cmp(secret, res_s));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
    // CurveParams curve;
    // pairing_t pairing;
    // pbc_param_t par;
    // pbc_param_init_set_str(par, curve.a_param.c_str());
    // pairing_init_pbc_param(pairing, par);
    // std::string policy = "(A and B and C) and (D or E or F) and (G and H and (I or J or K or L))";
    // LSSS parser(&pairing, policy);
    // std::cout << "DEBUG probe parser OK\n";
    // element_t secret;
    // element_init_Zr(secret, pairing);
    // element_set_si(secret, 42);
    // std::vector<element_t*> shares = parser.share(&secret);
    // std::cout << "DEBUG probe share OK\n";
    // element_t res_s;
    // element_init_Zr(res_s, pairing);
    // parser.reconstruct(std::vector<std::string>{"A", "B", "C", "D", "G", "H", "I"}, shares, &res_s);
    // std::cout << "DEBUG probe reconstruct OK\n";
    // if (!element_cmp(secret, res_s)) {
    //     std::cout << "CORRECT\n";
    // } else {
    //     std::cout << "WRONG\n";
    // }

    // return 0;
}