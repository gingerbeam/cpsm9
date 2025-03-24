#ifndef CRYPTO_BESM9_H
#define CRYPTO_BESM9_H

#include <memory>
#include <string>
#include <pbc/pbc.h>
#include <memory>
#include <vector>
#include <string>

#include <openssl/sha.h>

#include "crypto/kemsm9.h"

namespace crypto {

class besm9 : public kemsm9 {
public:
    std::vector<std::string> user_set;

    struct broadcast_ciphertext {
        std::vector<kemsm9::ciphertext> c;
    };

    besm9(std::string &param, std::vector<std::string> U);

    void BEncrypt(kemsm9::plaintext &ptx, std::vector<std::string> &ids, broadcast_ciphertext *ctxs);

    void BDecrypt(broadcast_ciphertext *ctxs, kemsm9::secretkey *sk, kemsm9::plaintext *ptx);
};

}

#endif