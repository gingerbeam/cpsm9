#ifndef CRYPTO_KEMSM9_H
#define CRYPTO_KEMSM9_H

#include <memory>
#include <string>
#include <pbc/pbc.h>
#include <memory>
#include <vector>
#include <string>

#include <openssl/sha.h>

namespace crypto {

class kemsm9 {
private:
    struct master_secretkey {
        element_t alpha;
    } msk;

    void Hash(std::string &m, element_t &res) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        const char *bytes = m.data();
        SHA256_Update(&sha256, bytes, m.size());
        SHA256_Final(hash, &sha256);
        element_from_hash(res, hash, SHA256_DIGEST_LENGTH);
    }
public:
    // element_t tmp;
    element_t hid;

    struct public_parameter {
        pairing_t pairing;
        element_t g1;
        element_t g2;
        element_t g_pub;
        element_t nu;
    } pp;

    struct secretkey {
        element_t k;
    };

    struct plaintext {
        element_t message;
    };

    struct ciphertext {
        element_t c_m;
        element_t c_prime;
        element_t c3;
    };
    // function as Setup
    kemsm9(std::string &param);
    kemsm9(int x) {}

    void Keygen(std::string &id, secretkey *sk);

    void Encrypt(plaintext ptx, std::string &id, ciphertext *ctx);

    void Decrypt(ciphertext *ctx, secretkey *sk, plaintext *ptx);

    // encapsulate message
    void Encaps(int message, plaintext *ptx) {
        element_init_GT(ptx->message, pp.pairing);
        element_set_si(ptx->message, message);
    }

    void RandomEncaps(plaintext *ptx) {
        element_init_GT(ptx->message, pp.pairing);
        element_random(ptx->message);
        // element_init_GT(m_tmp, pp.pairing);
        // element_set(m_tmp, ptx->message);
    }

    ~kemsm9();
};

}

#endif