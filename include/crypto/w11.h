#ifndef CRYPTO_W11_H
#define CRYPTO_W11_H

#include <memory>
#include <string>
#include "crypto/cpabe.h"

namespace crypto {

class w11 : public cpabe {
private:
    element_t g;
    element_t a;
    element_t alpha;
    element_t nu;
    element_t ga;
    int lenU;
    element_t *h;

public:
    w11(std::string &param): cpabe(param) {}
    ~w11() override;

    void Setup() override;
    void Setup(int U);

    void Keygen(std::vector<std::string> attrs) override;

    void Encrypt(plaintext ptx, std::string policy, ciphertext *ctx) override;

    std::string Decrypt(ciphertext ctx) override;
};

} // namespace crypto

#endif // CRYPTO_W11_H