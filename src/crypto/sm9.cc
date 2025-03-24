#include <iostream>
#include <string>
#include <random>
#include "crypto/sm9.h"

namespace crypto {

sm9::sm9(std::string &param) {
    // std::cout << "SM9: Scheme Setup.\n";
    // init pairing
    pbc_param_t par;
    pbc_param_init_set_str(par, param.c_str());
    pairing_init_pbc_param(pp.pairing, par);
    // init temporary element_t
    // element_init_Zr(tmp, pp.pairing);
    element_init_Zr(hid, pp.pairing);
    // init msk alpha
    element_init_Zr(msk.alpha, pp.pairing);
    element_random(msk.alpha);
    // rest of the parameters
    // g1
    element_init_G1(pp.g1, pp.pairing);
    element_random(pp.g1);
    // g2
    element_init_G2(pp.g2, pp.pairing);
    element_random(pp.g2);
    // g_pub
    element_init_G1(pp.g_pub, pp.pairing);
    element_pow_zn(pp.g_pub, pp.g1, msk.alpha);
    // nu
    element_init_GT(pp.nu, pp.pairing);
    element_pairing(pp.nu, pp.g_pub, pp.g2);
}

void sm9::Keygen(std::string &id, secretkey *sk) {
    // std::cout << "SM9: Keygen.\n";
    element_init_G2(sk->k, pp.pairing);
    // calculate the exponent    
    // element_t hid;
    // element_init_Zr(hid, pp.pairing);
    Hash(id, hid);
    element_add(hid, msk.alpha, hid); // hid = H(id) + alpha
    element_invert(hid, hid); // hid = 1 / (H(id) + alpha)
    element_mul(hid, hid, msk.alpha); // hid = alpha / (H(id) + alpha)
    element_pow_zn(sk->k, pp.g2, hid);
}

void sm9::Encrypt(plaintext ptx, std::string &id, ciphertext *ctx) {
    // std::cout << "SM9: Encrypt.\n";
    // secret random exponent
    element_t s;
    element_init_Zr(s, pp.pairing);
    element_random(s);
    // c_m = m nu^s
    element_init_GT(ctx->c_m, pp.pairing);
    element_pow_zn(ctx->c_m, pp.nu, s);
    element_mul(ctx->c_m, ctx->c_m, ptx.message);
    // c_prime = g_pub^s (g1^{HN})^s
    element_init_G1(ctx->c_prime, pp.pairing);
    // Hash(id, tmp); // tmp = H(id)
    // element_t hid;
    // element_init_Zr(hid, pp.pairing);
    Hash(id, hid);
    element_pow_zn(ctx->c_prime, pp.g1, hid);
    element_mul(ctx->c_prime, pp.g_pub, ctx->c_prime);
    element_pow_zn(ctx->c_prime, ctx->c_prime, s);
}

void sm9::Decrypt(ciphertext *ctx, secretkey *sk, plaintext *ptx) {
    // std::cout << "SM9: Decrypt.\n";
    element_t B;
    element_init_GT(B, pp.pairing);
    // B = e(g1^{s(alpha+HN)}, g2^{alpha/alpha+HN})
    element_pairing(B, ctx->c_prime, sk->k);
    element_invert(B, B);
    element_init_GT(ptx->message, pp.pairing);
    element_mul(ptx->message, B, ctx->c_m);
    element_clear(B);
}

sm9::~sm9() {
    // element_clear(tmp);
}

}