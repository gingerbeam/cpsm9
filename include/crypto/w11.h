#ifndef CRYPTO_W11_H
#define CRYPTO_W11_H

#include <memory>
#include <string>
#include <pbc/pbc.h>
#include <memory>
#include <vector>
#include <string>

#include "utils/lsss.h"

namespace crypto {

class w11 {
private:    
    struct master_secretkey {
        element_t alpha;
    } msk;
public:
    struct public_parameter {
        pairing_t pairing;
        element_t g;
        element_t nu;
        element_t ga;
        std::unordered_map<std::string, element_t*> h;
    } pp;
    
    struct attribute_set {
        std::vector<std::string> attrs;
    };

    struct secretkey {
        element_t k;
        element_t l;
        std::unordered_map<std::string, element_t*> kx;
    };

    struct plaintext {
        element_t message;
    };

    struct ciphertext {
        utils::LSSS *lsss_policy;
        element_t c_m;
        element_t c_prime;
        std::vector<element_t> c;
        std::vector<element_t> d;
        std::unordered_map<std::string, int> attr_to_idx;
    };
    // function as Setup
    w11(std::string &param, std::vector<std::string> Universe);

    void Keygen(attribute_set *A, secretkey *sk);

    void Encrypt(plaintext ptx, std::string policy, ciphertext *ctx);

    void Decrypt(ciphertext *ctx, attribute_set *A, secretkey *sk, plaintext *ptx);

    // encapsulate message
    void Encaps(int message, plaintext *ptx) {
        element_init_GT(ptx->message, pp.pairing);
        element_set_si(ptx->message, message);
    }

    void RandomEncaps(plaintext *ptx) {
        element_init_GT(ptx->message, pp.pairing);
        element_random(ptx->message);
    }

    ~w11();
};

} // namespace crypto

#endif // CRYPTO_W11_H