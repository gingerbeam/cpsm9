#ifndef CRYPTO_W11_H
#define CRYPTO_W11_H

#include <memory>
#include <string>
#include "crypto/cpabe.h"

namespace crypto {

class w11 : public cpabe {
public:
    ~w11() override;  // 显式声明析构函数
    std::unique_ptr<cpabe> clone() const override;

    void Setup() override;

    void Keygen() override;

    void Encrypt(const std::string& ptx) override;

    std::string Decrypt(const std::string& ctx) override;
};

} // namespace crypto

#endif // CRYPTO_W11_H