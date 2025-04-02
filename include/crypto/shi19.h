#ifndef CRYPTO_SHI19_H
#define CRYPTO_SHI19_H

#include <memory>
#include <string>
#include <pbc/pbc.h>
#include <memory>
#include <vector>
#include <string>
#include <algorithm>
#include <map>
#include <stack>
#include <regex>

#include <openssl/sha.h>

#include "crypto/kemsm9.h"
#include "crypto/besm9.h"

namespace crypto {

class shi19 : public besm9 {
private:
    std::string set_to_id(std::vector<std::string> &attrs);

    std::vector<std::vector<std::string>> access_structure;

public:
    typedef besm9::broadcast_ciphertext abe_ciphertext;

    shi19(std::string &param, std::vector<std::string> U);

    void shi19Keygen(std::vector<std::string> &attrs, secretkey *sk);

    void shi19Encrypt(plaintext &ptx, std::string policy, abe_ciphertext *ctx);
    void shi19Encrypt(plaintext &ptx, std::vector<std::vector<std::string>> &as, abe_ciphertext *ctx);

    void shi19Decrypt(abe_ciphertext *ctxs, std::vector<std::string> &attrs, secretkey *sk, plaintext *ptx);
};

}

#endif