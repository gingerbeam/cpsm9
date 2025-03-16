#ifndef CP_ABE_H
#define CP_ABE_H

#include <pbc/pbc.h>
#include <memory>
#include <vector>
#include <string>

#include "utils/lsss.h"

namespace crypto {

struct plaintext {
    element_t *message;
};

struct ciphertext {
    utils::LSSS *lsss_policy;
    int len;
    element_t *c;
};

struct secretkey {
    int len;
    element_t *k;
};

class cpabe {
protected:
    pairing_t pairing;

public:
    cpabe(std::string &param) {
        pbc_param_t par;
        pbc_param_init_set_str(par, param.c_str());
        pairing_init_pbc_param(pairing, par);
    }

    virtual ~cpabe() = default;

    // base methods
    virtual void Setup() = 0;
    virtual void Keygen(std::vector<std::string> attrs) = 0;
    virtual void Encrypt(plaintext ptx, std::string policy, ciphertext *ctx) = 0;
    virtual std::string Decrypt(ciphertext *ctx, std::vector<std::string> attrs, secretkey *sk) = 0;

    // getter
    pairing_t* getpairing() {return &pairing;}
};

}

#endif // CRYPTO_INTERFACE_HPP