#ifndef CRYPTO_LUSM9_H
#define CRYPTO_LUSM9_H

#include <memory>
#include <string>
#include <pbc/pbc.h>
#include <memory>
#include <vector>
#include <string>

#include "utils/lsss.h"

namespace crypto {

class lusm9 {
private:
    element_t tmp_2;
    element_t tmp_r1;
    element_t tmp_r2;
    element_t tmp_hn_alpha;

    // pp = {BP, g1, g2, g_pub, u, v, w, h, nu}
    struct public_parameter {
        pairing_t pairing;
        element_t g1;
        element_t g2;
        element_t u;
        element_t v;
        element_t w;
        element_t h;
        element_t g_pub;
        element_t nu; // nu = e(g_pub,g2)
        element_t gid;
    } pp;
    
    struct master_secretkey {
        element_t alpha;
    } msk;
public:
    struct attribute_set {
        std::vector<std::string> attrs;
    };

    struct secretkey {
        element_t k;
        element_t l;
        std::unordered_map<std::string, element_t*> kx1;
        std::unordered_map<std::string, element_t*> kx2;
    };

    struct plaintext {
        element_t message;
    };

    struct ciphertext {
        utils::LSSS *lsss_policy;
        element_t c_m;
        element_t c_prime;
        std::vector<element_t> ci1;
        std::vector<element_t> ci2;
        std::vector<element_t> ci3;
        std::unordered_map<std::string, int> attr_to_idx;
    };
    void Hash(element_t &m, element_t &res);
    void HtoZ(std::string &m, element_t &res);

    // function as Setup
    lusm9(std::string &param);

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

    ~lusm9();
};

} // namespace crypto

#endif // CRYPTO_W11_H