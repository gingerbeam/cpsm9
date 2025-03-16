#include <iostream>
#include <string>
#include <random>
#include "crypto/w11.h"

namespace crypto {

w11::~w11() {
    element_clear(g);
    element_clear(a);
    element_clear(alpha);
    element_clear(nu);
    element_clear(ga);
    delete[] h;
}

void w11::Setup() {}

void w11::Setup(int U) {
    std::cout << "Waters11: Scheme Setup.\n";
    lenU = U;
    element_init_G1(g, pairing);
    element_init_Zr(a, pairing);
    element_init_Zr(alpha, pairing);
    element_init_GT(nu, pairing);
    element_init_G1(ga, pairing);
    h = new element_t[lenU];
    for (int i = 0; i < lenU; i++) {
        element_init_G1(h[i], pairing);
    }
    // set up public parameters
    element_random(g);
    element_random(a);
    element_random(alpha);
    pairing_apply(nu, g, g, pairing);
    element_pow_zn(nu, nu, alpha);
    element_pow_zn(ga, g, a);
}

void w11::Keygen(std::vector<std::string> attrs) {
    std::cout << "Waters11: Keygen.\n";

}

void w11::Encrypt(plaintext ptx, std::string policy, ciphertext *ctx) {
    std::cout << "Waters11: Encrypt.\n";
    utils::LSSS lsss(policy);
    // element_t s;
    // element_init_Zr(s, pairing);
    std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<> dis(1, 100);
    int rs = dis(gen);
    element_t s;
    element_init_Zr(s, pairing);
    element_set_si(s, rs);
    int *shares;
    lsss.share(rs, &shares);
    int l = lsss.getl();
    element_t *lambda = new element_t[l];
    for (int i = 0; i < lsss.getl(); i++) {
        element_init_Zr(lambda[i], pairing);
        element_set_si(lambda[i], shares[i]);
    }
    element_t cm;
    element_init_G1(cm, pairing);
    element_t nus;
    element_init_GT(nus, pairing);
    element_pow_zn(nus, nu, s);
    element_mul(cm, *(ptx.message), nus);
    // cm = m * nu^s
    element_t cp;
    element_init_G1(cp, pairing);
    element_pow_zn(cp, g, s);
    element_t *ci = new element_t[l];
    element_t *di = new element_t[l];
    for (int i = 0; i < l; i++) {
        element_t ri;
        element_init_Zr(ri, pairing);
        element_random(ri);
        // ci
        element_init_G1(ci[i], pairing);
        element_pow_zn(ci[i], ga, lambda[i]);
        element_t tmp;
        element_init_G1(tmp, pairing);
        element_pow_zn(tmp, h[i], ri);
        element_mul(ci[i], ci[i], h[i]);
        // di
        element_init_G1(di[i], pairing);
        element_pow_zn(di[i], g, ri);
    }
    (ctx->c) = new element_t[l + 2];
    for (int i = 0; i < l + 2; ++i) element_init_G1((ctx->c)[i], pairing);
    element_set((ctx->c)[0], cm);
    element_set((ctx->c)[1], cp);
    for (int i = 2; i < l + 2; ++i) element_set((ctx->c)[i], ci[i - 2]);
}

std::string w11::Decrypt(ciphertext ctx) {
    std::cout << "Waters11: Decrypt.\n";
    return "Waters11: Decrypt.\n";
}

} // namespace crypto