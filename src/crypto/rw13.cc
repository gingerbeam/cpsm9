#include <iostream>
#include <string>
#include <random>
#include "crypto/rw13.h"

#include <openssl/sha.h>

namespace crypto {

void rw13::HtoZ(std::string &m, element_t &res) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    const char *bytes = m.data();
    SHA256_Update(&sha256, bytes, m.size());
    SHA256_Final(hash, &sha256);
    element_from_hash(res, hash, SHA256_DIGEST_LENGTH);
}

rw13::rw13(std::string &param) {
    // init pairing
    pbc_param_t par;
    pbc_param_init_set_str(par, param.c_str());
    pairing_init_pbc_param(pp.pairing, par);
    // init element_t
    element_init_G1(tmp1, pp.pairing);
    element_init_G2(tmp2, pp.pairing);
    // alpha
    element_init_Zr(msk.alpha, pp.pairing);
    element_random(msk.alpha);
    // g
    element_init_G1(pp.g1, pp.pairing);
    element_random(pp.g1);
    element_init_G2(pp.g2, pp.pairing);
    element_random(pp.g2);
    // u
    element_init_G2(pp.u, pp.pairing);
    element_random(pp.u);
    // h
    element_init_G2(pp.h, pp.pairing);
    element_random(pp.h);
    // w
    element_init_G2(pp.w, pp.pairing);
    element_random(pp.w);
    // v
    element_init_G2(pp.v, pp.pairing);
    element_random(pp.v);
    // nu
    element_init_GT(pp.nu, pp.pairing);
    element_pairing(pp.nu, pp.g1, pp.g2);
    element_pow_zn(pp.nu, pp.nu, msk.alpha);
}

void rw13::Keygen(attribute_set *A, secretkey *sk) {
    // randomness
    element_t r;
    element_init_Zr(r, pp.pairing);
    element_random(r);
    // K_0 = g2^alpha w^r
    element_init_G2(sk->k0, pp.pairing);
    element_pow_zn(sk->k0, pp.g2, msk.alpha);
    element_pow_zn(tmp2, pp.w, r);
    element_mul(sk->k0, sk->k0, tmp2);
    // K_1 = g1^r
    element_init_G1(sk->k1, pp.pairing);
    element_pow_zn(sk->k1, pp.g1, r);
    // v^{-r}
    element_pow_zn(tmp2, pp.v, r);
    element_invert(tmp2, tmp2);
    // for all a in attrs, Kx = h_x^t
    element_t ra;
    element_init_Zr(ra, pp.pairing);
    element_t _a;
    element_init_Zr(_a, pp.pairing);
    for (auto a : A->attrs) {
        // randomness
        element_random(ra);
        // ka2
        element_t *ka2 = (element_t *)(new element_t);
        element_init_G1(*ka2, pp.pairing);
        element_pow_zn(*ka2, pp.g1, ra);
        sk->kx2.insert({a, ka2});
        // ka3
        element_t *ka3 = (element_t *)(new element_t);
        element_init_G2(*ka3, pp.pairing);
        // A_tao as element_t
        HtoZ(a, _a);
        element_pow_zn(*ka3, pp.u, _a);
        element_mul(*ka3, *ka3, pp.h);
        element_pow_zn(*ka3, *ka3, ra);
        element_mul(*ka3, *ka3, tmp2);
        
        sk->kx3.insert({a, ka3});
    }
    element_clear(r);
    element_clear(ra);
    element_clear(_a);
}

void rw13::Encrypt(plaintext ptx, std::string policy, ciphertext *ctx) {
    // std::cout << "RW13: Encrypt.\n";
    // init lsss policy
    ctx->lsss_policy = new utils::LSSS(&pp.pairing, policy);
    // secret exponent s
    element_t s;
    element_init_Zr(s, pp.pairing);
    element_random(s);
    // cm = m * nu^s
    element_init_GT(ctx->c_m, pp.pairing);
    element_pow_zn(ctx->c_m, pp.nu, s);
    element_mul(ctx->c_m, ctx->c_m, ptx.message);
    // c_0 = g1^s
    element_init_G1(ctx->c_0, pp.pairing);
    element_pow_zn(ctx->c_0, pp.g1, s);
    // c_i_1, c_i_2, c_i_3
    ctx->ci1 = std::vector<element_t>(ctx->lsss_policy->get_l());
    ctx->ci2 = std::vector<element_t>(ctx->lsss_policy->get_l());
    ctx->ci3 = std::vector<element_t>(ctx->lsss_policy->get_l());
    auto lambda = ctx->lsss_policy->share(&s);
    element_t _rhoi;
    element_init_Zr(_rhoi, pp.pairing);
    element_t ti;
    element_init_Zr(ti, pp.pairing);
    for (int i = 0; i < ctx->lsss_policy->get_l(); i++) {
        element_random(ti);
        // c_i_1 = w^{lambda_i} v^{ti}
        element_init_G2(ctx->ci1[i], pp.pairing);
        element_pow_zn(ctx->ci1[i], pp.w, *(lambda[i]));
        element_pow_zn(tmp2, pp.v, ti);
        element_mul(ctx->ci1[i], ctx->ci1[i], tmp2);
        // c_i_3 = g^{ti}
        element_init_G1(ctx->ci3[i], pp.pairing);
        element_pow_zn(ctx->ci3[i], pp.g1, ti);
        // c_i_2 = (u^{rho(i)}h)^{-ti}
        element_init_G2(ctx->ci2[i], pp.pairing);
        std::string rhoi = ctx->lsss_policy->rho_map(i);
        HtoZ(rhoi, _rhoi);
        element_pow_zn(ctx->ci2[i], pp.u, _rhoi);
        element_mul(ctx->ci2[i], ctx->ci2[i], pp.h);
        element_pow_zn(ctx->ci2[i], ctx->ci2[i], ti);
        element_invert(ctx->ci2[i], ctx->ci2[i]);
    }
    // Clear temporary elements
    element_clear(s);
    element_clear(_rhoi);
    element_clear(ti);
}

void rw13::Decrypt(ciphertext *ctx, attribute_set *A, secretkey *sk, plaintext *ptx) {
    element_t tmp_nemu;
    element_t tmp_deno;
    element_init_GT(tmp_nemu, pp.pairing);
    element_init_GT(tmp_deno, pp.pairing);
    element_t tmp_gt1;
    element_t tmp_gt2;
    element_t tmp_gt3;
    element_init_GT(tmp_gt1, pp.pairing);
    element_init_GT(tmp_gt2, pp.pairing);
    element_init_GT(tmp_gt3, pp.pairing);

    // std::cout << "RW13: Decrypt.\n";
    // attributes to omega
    auto omega = (ctx->lsss_policy)->retriveOmega(A->attrs);
    // e(C_0, K_0)
    element_pairing(tmp_nemu, ctx->c_0, sk->k0);
    // prod e(C_i_1, K_1) e(C_i_2, K_rho(i)_2) e(C_i_3, K_rho(i)_3)
    // retirve I
    std::vector<int> I = ctx->lsss_policy->get_match(A->attrs);
    element_set1(tmp_deno);
    for (auto row : I) {
        // e(C_i_1, K_1)
        element_pairing(tmp_gt1, sk->k1, ctx->ci1[row]);
        // e(C_i_2, K_rho(i)_2)
        element_pairing(tmp_gt2, *(sk->kx2[ctx->lsss_policy->rho_map(row)]), ctx->ci2[row]);
        // e(C_i_3, K_rho(i)_3)
        element_pairing(tmp_gt3, ctx->ci3[row], *(sk->kx3[ctx->lsss_policy->rho_map(row)]));
        element_mul(tmp_gt1, tmp_gt1, tmp_gt2);
        element_mul(tmp_gt1, tmp_gt1, tmp_gt3);
        element_pow_zn(tmp_gt1, tmp_gt1, *(omega[row]));
        element_mul(tmp_deno, tmp_deno, tmp_gt1);
    }
    element_invert(tmp_deno, tmp_deno);
    element_mul(tmp_nemu, tmp_nemu, tmp_deno);
    element_invert(tmp_nemu, tmp_nemu);
    element_init_GT(ptx->message, pp.pairing);
    element_mul(ptx->message, tmp_nemu, ctx->c_m);
    // Clear temporary elements
    element_clear(tmp_nemu);
    element_clear(tmp_deno);
    element_clear(tmp_gt1);
    element_clear(tmp_gt2);
    element_clear(tmp_gt3);
}

rw13::~rw13() {
    // Clear elements in the pairing parameters
    element_clear(pp.g1);
    element_clear(pp.g2);
    element_clear(pp.u);
    element_clear(pp.h);
    element_clear(pp.w);
    element_clear(pp.v);
    element_clear(pp.nu);
    element_clear(msk.alpha);
    element_clear(tmp1);
    element_clear(tmp2);
}

} // namespace crypto