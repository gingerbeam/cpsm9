#include <iostream>
#include <string>
#include <random>
#include "crypto/w11.h"

namespace crypto {

w11::w11(std::string &param, std::vector<std::string> Universe) {
    // std::cout << "Waters11: Scheme Setup.\n";
    // init pairing
    pbc_param_t par;
    pbc_param_init_set_str(par, param.c_str());
    pairing_init_pbc_param(pp.pairing, par);
    // init temporary element_t
    element_init_G1(tmp, pp.pairing);
    // sk->alpha
    element_init_Zr(msk.alpha, pp.pairing);
    element_random(msk.alpha);
    // rest of pp
    element_init_G1(pp.g, pp.pairing);
    element_random(pp.g);
    // nu
    element_init_GT(pp.nu, pp.pairing);
    element_pairing(pp.nu, pp.g, pp.g);
    element_pow_zn(pp.nu, pp.nu, msk.alpha);
    // secret randomness a
    element_t a;
    element_init_Zr(a, pp.pairing);
    element_random(a);
    // g^a
    element_init_G1(pp.ga, pp.pairing);
    element_pow_zn(pp.ga, pp.g, a);
    // set up attribute parameters
    for (auto x : Universe) {
        element_t *hx = (element_t *)(new element_t);
        element_init_G1(*hx, pp.pairing);
        element_random(*hx);
        pp.h.insert({x, hx});
    }
    // std::cout << "Waters11: Scheme Setup Done.\n";
}

void w11::Keygen(attribute_set *A, secretkey *sk) {
    // std::cout << "Waters11: Keygen.\n";
    // randomness
    element_t t;
    element_init_Zr(t, pp.pairing);
    element_random(t);
    // K = g^alpha g^at
    element_init_G1(sk->k, pp.pairing);
    element_pow_zn(sk->k, pp.g, msk.alpha);
    element_pow_zn(tmp, pp.ga, t);
    element_mul(sk->k, sk->k, tmp);
    // L = g^t
    element_init_G1(sk->l, pp.pairing);
    element_pow_zn(sk->l, pp.g, t);
    // for all a in attrs, Kx = h_x^t
    for (auto a : A->attrs) {
        element_t *ka = (element_t *)(new element_t);
        element_init_G1(*ka, pp.pairing);
        element_pow_zn(*ka, *(pp.h[a]), t);
        sk->kx.insert({a, ka});
    }
    element_clear(t);
    // std::cout << "Waters11: Scheme Keygen Done.\n";
}

void w11::Encrypt(plaintext ptx, std::string policy, ciphertext *ctx) {
    // std::cout << "Waters11: Encrypt.\n";
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
    // g_prime = g^s
    element_init_G1(ctx->c_prime, pp.pairing);
    element_pow_zn(ctx->c_prime, pp.g, s);
    // c_i & d_i
    ctx->c = std::vector<element_t>(ctx->lsss_policy->get_l());
    ctx->d = std::vector<element_t>(ctx->lsss_policy->get_l());
    auto lambda = ctx->lsss_policy->share(&s);
    for (int i = 0; i < ctx->lsss_policy->get_l(); i++) {
        element_t ri;
        element_init_Zr(ri, pp.pairing);
        element_random(ri);
        // c_i = ga^{\lambda_i} h_{\rho(i)}^{-r_i}
        element_init_G1(ctx->c[i], pp.pairing);
        element_pow_zn(ctx->c[i], pp.ga, *(lambda[i]));
        element_pow_zn(tmp, *(pp.h[ctx->lsss_policy->rho_map(i)]), ri);
        element_invert(tmp, tmp);
        element_mul(ctx->c[i], ctx->c[i], tmp);
        // d_i = g^{r_i}
        element_init_G1(ctx->d[i], pp.pairing);
        element_pow_zn(ctx->d[i], pp.g, ri);
    }
    // Clear temporary elements
    element_clear(s);
}

void w11::Decrypt(ciphertext *ctx, attribute_set *A, secretkey *sk, plaintext *ptx) {
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
    // prod e(C_i, L)e(D_i, K_rho(i))
    // retirve I
    std::vector<int> I = ctx->lsss_policy->get_match(A->attrs);
    element_set1(tmp_deno);
    for (auto row : I) {
        element_pairing(tmp_gt1, ctx->c[row], sk->l);
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
    // Clear temporary elements
    element_clear(tmp_nemu);
    element_clear(tmp_deno);
    element_clear(tmp_gt1);
    element_clear(tmp_gt2);
    // std::cout << "Waters11: Scheme Decrypt Done.\n";
}

w11::~w11() {
    // Clear elements in the pairing parameters
    element_clear(pp.g);
    element_clear(pp.ga);
    element_clear(pp.nu);
    element_clear(msk.alpha);
    element_clear(tmp);
}

} // namespace crypto