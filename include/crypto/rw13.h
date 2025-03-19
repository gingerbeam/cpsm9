#ifndef CRYPTO_RW13_H
#define CRYPTO_RW13_H

#include <memory>
#include <string>
#include <pbc/pbc.h>
#include <memory>
#include <vector>
#include <string>

#include "utils/lsss.h"

namespace crypto {

class rw13 {
private:
    // pp = {BP, g, u, h, w, v, nu}
    struct public_parameter {
        pairing_t pairing;
        element_t g;
        element_t u;
        element_t h;
        element_t w;
        element_t v;
        element_t alpha;
        element_t nu; // nu = e(g,g)^alpha
        // std::unordered_map<std::string, element_t*> h;
    } pp;
    
    struct master_secretkey {
        element_t alpha;
    } msk;

    element_t g_pub;
public:
    struct attribute_set {
        std::vector<std::string> attrs;
    };

    struct secretkey {
        element_t k0;
        element_t k1;
        std::unordered_map<std::string, element_t*> kx2;
        std::unordered_map<std::string, element_t*> kx3;
    };

    struct plaintext {
        element_t message;
    };

    struct ciphertext {
        utils::LSSS *lsss_policy;
        element_t c_m;
        element_t c_0;
        std::vector<element_t> ci1;
        std::vector<element_t> ci2;
        std::vector<element_t> ci3;
        std::unordered_map<std::string, int> attr_to_idx;
    };
    // function as Setup
    rw13(std::string &param);

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

    ~rw13();
};

} // namespace crypto

#endif // CRYPTO_W11_H