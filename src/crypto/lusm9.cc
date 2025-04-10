#include <iostream>
#include <string>
#include <random>
#include "crypto/lusm9.h"

#include <openssl/sha.h>

namespace crypto {
// sm9 secure hash
void lusm9::Hash(element_t &m, element_t &res) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned char bytes1[element_length_in_bytes(m)];
    element_to_bytes(bytes1, m);
    SHA256_Update(&sha256, bytes1, sizeof(bytes1));
    SHA256_Final(hash, &sha256);
    element_from_hash(res, hash, SHA256_DIGEST_LENGTH);
}

void lusm9::HtoZ(std::string &m, element_t &res) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    const char *bytes = m.data();
    SHA256_Update(&sha256, bytes, m.size());
    SHA256_Final(hash, &sha256);
    element_from_hash(res, hash, SHA256_DIGEST_LENGTH);
}

lusm9::lusm9(std::string &param) {
    // init pairing
    pbc_param_t par;
    pbc_param_init_set_str(par, param.c_str());
    pairing_init_pbc_param(pp.pairing, par);
    // init temporary element_t objects
    element_init_G2(tmp_2, pp.pairing);
    element_init_Zr(tmp_r1, pp.pairing);
    element_init_Zr(tmp_r2, pp.pairing);
    element_init_Zr(tmp_hn_alpha, pp.pairing);
    // g1
    element_init_G1(pp.g1, pp.pairing);
    element_random(pp.g1);
    // g2
    element_init_G2(pp.g2, pp.pairing);
    element_random(pp.g2);
    // u
    element_init_G2(pp.u, pp.pairing);
    element_random(pp.u);
    // v
    element_init_G2(pp.v, pp.pairing);
    element_random(pp.v);
    // w
    element_init_G2(pp.w, pp.pairing);
    element_random(pp.w);
    // h
    element_init_G2(pp.h, pp.pairing);
    element_random(pp.h);
    // alpha
    element_init_Zr(msk.alpha, pp.pairing);
    element_random(msk.alpha);
    // g_pub
    element_init_G1(pp.g_pub, pp.pairing);
    element_pow_zn(pp.g_pub, pp.g1, msk.alpha);
    // nu
    element_init_GT(pp.nu, pp.pairing);
    element_pairing(pp.nu, pp.g_pub, pp.g2);
    // generate HN
    element_init_Zr(pp.gid, pp.pairing);
    element_random(pp.gid);
}

void lusm9::Keygen(attribute_set *A, secretkey *sk) {
    // HN+alpha
    Hash(pp.gid, tmp_hn_alpha);
    element_add(tmp_hn_alpha, tmp_hn_alpha, msk.alpha);
    element_invert(tmp_hn_alpha, tmp_hn_alpha);
    // randomness
    element_t t;
    element_init_Zr(t, pp.pairing);
    element_random(t);
    // K = g2^{alpha/HN+alpha} u^{t/HN+alpha}
    element_init_G2(sk->k, pp.pairing);
    element_mul(tmp_r1, msk.alpha, tmp_hn_alpha);
    element_pow_zn(sk->k, pp.g2, tmp_r1);
    element_mul(tmp_r1, t, tmp_hn_alpha);
    element_pow_zn(tmp_2, pp.u, tmp_r1);
    element_mul(sk->k, sk->k, tmp_2);
    // L = g1^t
    element_init_G1(sk->l, pp.pairing);
    element_pow_zn(sk->l, pp.g1, t);
    // v^{-t}
    element_pow_zn(tmp_2, pp.v, t);
    element_invert(tmp_2, tmp_2);
    // for all a in attrs, choose t_x
    for (auto a : A->attrs) {
        element_t *ka1 = (element_t *)(new element_t);
        element_init_G1(*ka1, pp.pairing);
        element_t *ka2 = (element_t *)(new element_t);
        element_init_G2(*ka2, pp.pairing);
        // A_tao as element_t
        HtoZ(a, tmp_r1);
        element_pow_zn(*ka2, pp.w, tmp_r1);
        // randomness
        element_random(tmp_r1);
        // ka1 = g_1^{t_x}
        element_pow_zn(*ka1, pp.g1, tmp_r1);
        sk->kx1.insert({a, ka1});
        // ka2 = (w^x h)^{t_x}v^{-t}
        element_mul(*ka2, *ka2, pp.h);
        element_pow_zn(*ka2, *ka2, tmp_r1);
        element_mul(*ka2, *ka2, tmp_2);
        sk->kx2.insert({a, ka2});
    }
}

void lusm9::Encrypt(plaintext ptx, std::string policy, ciphertext *ctx) {
    // init lsss policy
    ctx->lsss_policy = new utils::LSSS(&pp.pairing, policy);
    // secret exponent s
    element_random(tmp_r1);
    // cm = m * nu^s
    element_init_GT(ctx->c_m, pp.pairing);
    element_pow_zn(ctx->c_m, pp.nu, tmp_r1);
    element_mul(ctx->c_m, ctx->c_m, ptx.message);
    // c_0 = g_pub^s (g^HN)^s
    Hash(pp.gid, tmp_hn_alpha);
    element_init_G1(ctx->c_prime, pp.pairing);
    element_pow_zn(ctx->c_prime, pp.g1, tmp_hn_alpha);
    element_mul(ctx->c_prime, ctx->c_prime, pp.g_pub);
    element_pow_zn(ctx->c_prime, ctx->c_prime, tmp_r1);
    // c_i
    ctx->ci1 = std::vector<element_t>(ctx->lsss_policy->get_l());
    ctx->ci2 = std::vector<element_t>(ctx->lsss_policy->get_l());
    ctx->ci3 = std::vector<element_t>(ctx->lsss_policy->get_l());
    auto lambda = ctx->lsss_policy->share(&tmp_r1);
    for (int i = 0; i < ctx->lsss_policy->get_l(); i++) {
        element_init_G2(ctx->ci1[i], pp.pairing);
        element_init_G2(ctx->ci2[i], pp.pairing);
        std::string rhoi = ctx->lsss_policy->rho_map(i);
        HtoZ(rhoi, tmp_r1);
        element_pow_zn(ctx->ci2[i], pp.w, tmp_r1);
        // randomness
        element_random(tmp_r1);
        // c_i_1 = u^{lambda_i} v^{ri}
        element_pow_zn(ctx->ci1[i], pp.u, *(lambda[i]));
        element_pow_zn(tmp_2, pp.v, tmp_r1);
        element_mul(ctx->ci1[i], ctx->ci1[i], tmp_2);
        // c_i_2 = (w^{rho(i)}h)^{-ri}
        element_mul(ctx->ci2[i], ctx->ci2[i], pp.h);
        element_pow_zn(ctx->ci2[i], ctx->ci2[i], tmp_r1);
        element_invert(ctx->ci2[i], ctx->ci2[i]);
        // c_i_3 = g1^{ri}
        element_init_G1(ctx->ci3[i], pp.pairing);
        element_pow_zn(ctx->ci3[i], pp.g1, tmp_r1);
    }
}

void lusm9::Decrypt(ciphertext *ctx, attribute_set *A, secretkey *sk, plaintext *ptx) {
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
    // attributes to omega
    auto omega = (ctx->lsss_policy)->retriveOmega(A->attrs);
    // e(C_prime, K)
    element_pairing(tmp_nemu, ctx->c_prime, sk->k);
    // prod e(L, C_i_1) e(K_rho(i)_1, C_i_2) e(C_i_3, K_rho(i)_2)
    // retirve I
    std::vector<int> I = ctx->lsss_policy->get_match(A->attrs);
    element_set1(tmp_deno);
    for (auto row : I) {
        // e(L, C_i_1)
        element_pairing(tmp_gt1, sk->l, ctx->ci1[row]);
        // e(K_rho(i)_1, C_i_2)
        element_pairing(tmp_gt2, *(sk->kx1[ctx->lsss_policy->rho_map(row)]), ctx->ci2[row]);
        // e(C_i_3, K_rho(i)_2)
        element_pairing(tmp_gt3, ctx->ci3[row], *(sk->kx2[ctx->lsss_policy->rho_map(row)]));
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
    element_clear(tmp_nemu);
    element_clear(tmp_deno);
    element_clear(tmp_gt1);
    element_clear(tmp_gt2);
    element_clear(tmp_gt3);
}

lusm9::~lusm9() {
    element_clear(pp.g1);
    element_clear(pp.g2);
    element_clear(pp.u);
    element_clear(pp.v);
    element_clear(pp.w);
    element_clear(pp.h);
    element_clear(pp.g_pub);
    element_clear(pp.nu);
    element_clear(msk.alpha);
    element_clear(tmp_2);
    element_clear(tmp_r1);
    element_clear(tmp_r2);
    element_clear(tmp_hn_alpha);
}
} // namespace crypto