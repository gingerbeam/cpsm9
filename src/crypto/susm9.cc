#include <iostream>
#include <string>
#include <random>
#include "crypto/susm9.h"

// #include "utils/hash.h"
#include <openssl/sha.h>

namespace crypto {

void susm9::Hash(element_t &m, element_t &res) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned char bytes1[element_length_in_bytes(m)];
    element_to_bytes(bytes1, m);
    SHA256_Update(&sha256, bytes1, sizeof(bytes1));
    SHA256_Final(hash, &sha256);
    element_from_hash(res, hash, SHA256_DIGEST_LENGTH);
}

// Constructor as Setup
susm9::susm9(std::string &param, std::vector<std::string> Universe) {
    // std::cout << "SUSM9: Scheme Setup.\n";
    // init pairing
    pbc_param_t par;
    pbc_param_init_set_str(par, param.c_str());
    pairing_init_pbc_param(pp.pairing, par);
    // rest of pp
    element_init_G1(pp.g1, pp.pairing);
    element_random(pp.g1);
    element_init_G2(pp.g2, pp.pairing);
    element_random(pp.g2);
    element_init_G2(pp.u, pp.pairing);
    element_random(pp.u);
    // alpha
    element_init_Zr(msk.alpha, pp.pairing);
    element_random(msk.alpha);
    // g_pub
    element_init_G1(pp.g_pub, pp.pairing);
    element_pow_zn(pp.g_pub, pp.g1, msk.alpha);
    // nu
    element_init_GT(pp.nu, pp.pairing);
    element_pairing(pp.nu, pp.g_pub, pp.g2);
    // set up attribute parameters
    for (auto x : Universe) {
        element_t *hx = (element_t *)(new element_t);
        element_init_G2(*hx, pp.pairing);
        element_random(*hx);
        pp.h.insert({x, hx});
    }
    // generate gid for HN
    element_init_Zr(pp.gid, pp.pairing);
}

void susm9::Keygen(attribute_set *A, secretkey *sk) {
    // temp
    element_t tmp1;
    element_t tmp2;
    element_init_G1(tmp1, pp.pairing);
    element_init_G2(tmp2, pp.pairing);
    element_t tmp;
    element_init_Zr(tmp, pp.pairing);

    // std::cout << "SUSM9: Keygen.\n";
    // HN+alpha
    element_t HN_alpha;
    element_init_Zr(HN_alpha, pp.pairing);
    Hash(pp.gid, HN_alpha);
    element_add(HN_alpha, HN_alpha, msk.alpha);
    element_invert(HN_alpha, HN_alpha);
    // randomness
    element_t t;
    element_init_Zr(t, pp.pairing);
    element_random(t);
    // K = g2^{alpha/HN+alpha} u^{t/HN+alpha}
    element_init_G2(sk->k, pp.pairing);
    element_mul(tmp, msk.alpha, HN_alpha);
    element_pow_zn(sk->k, pp.g2, tmp);
    element_mul(tmp, t, HN_alpha);
    element_pow_zn(tmp2, pp.u, tmp);
    element_mul(sk->k, sk->k, tmp2);
    // L = g1^t
    element_init_G1(sk->l, pp.pairing);
    element_pow_zn(sk->l, pp.g1, t);
    // for all a in attrs, Kx = h_x^t
    for (auto a : A->attrs) {
        element_t *ka = (element_t *)(new element_t);
        element_init_G2(*ka, pp.pairing);
        element_pow_zn(*ka, *(pp.h[a]), t);
        sk->kx.insert({a, ka});
    }
    // std::cout << "SUSM9: Scheme Keygen Done.\n";

    // Clear temporary elements
    element_clear(tmp1);
    element_clear(tmp2);
    element_clear(tmp);
    element_clear(HN_alpha);
    element_clear(t);
}

void susm9::Encrypt(plaintext ptx, std::string policy, ciphertext *ctx) {
    element_t tmp;
    element_init_G2(tmp, pp.pairing);
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
    // g_prime = (g1^HN g_pub)^s
    element_t HN;
    element_init_Zr(HN, pp.pairing);
    Hash(pp.gid, HN);
    element_init_G1(ctx->c_prime, pp.pairing);
    element_pow_zn(ctx->c_prime, pp.g1, HN);
    element_mul(ctx->c_prime, ctx->c_prime, pp.g_pub);
    element_pow_zn(ctx->c_prime, ctx->c_prime, s);
    // c_i = u^{\lambda_i} h_{\rho(i)}^{-r_i}
    // d_i = g1^{r_i}
    ctx->c = std::vector<element_t>(ctx->lsss_policy->get_l());
    ctx->d = std::vector<element_t>(ctx->lsss_policy->get_l());
    auto lambda = ctx->lsss_policy->share(&s);
    element_t ri;
    element_init_Zr(ri, pp.pairing);
    for (int i = 0; i < ctx->lsss_policy->get_l(); i++) {
        element_random(ri);
        // ci
        element_init_G2(ctx->c[i], pp.pairing);
        element_pow_zn(ctx->c[i], pp.u, *(lambda[i]));
        element_pow_zn(tmp, *(pp.h[ctx->lsss_policy->rho_map(i)]), ri);
        element_invert(tmp, tmp);
        element_mul(ctx->c[i], ctx->c[i], tmp);
        // di
        element_init_G1(ctx->d[i], pp.pairing);
        element_pow_zn(ctx->d[i], pp.g1, ri);
    }

    // Clear temporary elements
    element_clear(tmp);
    element_clear(s);
    element_clear(ri);
}

void susm9::Decrypt(ciphertext *ctx, attribute_set *A, secretkey *sk, plaintext *ptx) {
    element_t tmp_nemu;
    element_t tmp_deno;
    element_init_GT(tmp_nemu, pp.pairing);
    element_init_GT(tmp_deno, pp.pairing);
    element_t tmp_gt1;
    element_t tmp_gt2;
    element_init_GT(tmp_gt1, pp.pairing);
    element_init_GT(tmp_gt2, pp.pairing);

    // std::cout << "Waters11: Decrypt.\n";
    // attributes to omega
    auto omega = (ctx->lsss_policy)->retriveOmega(A->attrs);
    // e(C', K)
    element_pairing(tmp_nemu, ctx->c_prime, sk->k);
    // prod e(L, C_i)e(D_i, K_rho(i))
    // retirve I
    std::vector<int> I = ctx->lsss_policy->get_match(A->attrs);
    element_set1(tmp_deno);
    for (auto row : I) {
        element_pairing(tmp_gt1, sk->l, ctx->c[row]);
        element_pairing(tmp_gt2, ctx->d[row], *(sk->kx[ctx->lsss_policy->rho_map(row)]));
        element_mul(tmp_gt1, tmp_gt1, tmp_gt2);
        element_pow_zn(tmp_gt1, tmp_gt1, *(omega[row]));
        element_mul(tmp_deno, tmp_deno, tmp_gt1);
    }
    element_invert(tmp_deno, tmp_deno);
    element_mul(tmp_nemu, tmp_nemu, tmp_deno);
    element_invert(tmp_nemu, tmp_nemu);
    element_init_GT(ptx->message, pp.pairing);
    element_mul(ptx->message, tmp_nemu, ctx->c_m);

    // std::cout << "Waters11: Scheme Decrypt Done.\n";

    // Clear temporary elements
    element_clear(tmp_nemu);
    element_clear(tmp_deno);
    element_clear(tmp_gt1);
    element_clear(tmp_gt2);
}

susm9::~susm9() {
    // Clear elements in the pairing parameters
    element_clear(pp.g1);
    element_clear(pp.g2);
    element_clear(pp.u);
    element_clear(pp.g_pub);
    element_clear(pp.nu);
    element_clear(msk.alpha);
    element_clear(pp.gid);
}
} // namespace crypto