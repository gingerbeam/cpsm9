#include "crypto/besm9.h"

namespace crypto {

besm9::besm9 (std::string &param, std::vector<std::string> U) : kemsm9(param) {
    user_set = U;
}

void besm9::BEncrypt(plaintext &ptx, std::vector<std::string> &ids, broadcast_ciphertext *ctxs) {
    ctxs->c = std::vector<kemsm9::ciphertext>(ids.size());
    for (int i = 0; i < ids.size(); ++i) {
        kemsm9::ciphertext cid;
        kemsm9::Encrypt(ptx, ids[i], &cid);
        ctxs->c[i] = cid;
    }
}

void besm9::BDecrypt(broadcast_ciphertext *ctxs, secretkey *sk, plaintext *ptx) {
    element_init_GT(ptx->message, pp.pairing);
    for (int i = 0; i < ctxs->c.size(); ++i) {
        kemsm9::plaintext res;
        kemsm9::Decrypt(&ctxs->c[i], sk, &res);
        if (!element_is0(res.message)) {
            element_set(ptx->message, res.message);
            return;
        }
    }
    element_set0(ptx->message);
}

}