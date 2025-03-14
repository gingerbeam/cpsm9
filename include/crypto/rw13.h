#ifndef CRYPTO_RW13_H
#define CRYPTO_RW13_H

#include <memory>
#include <string>
#include "crypto/cpabe.h"

namespace crypto {

class rw13 : public cpabe {
public:
    ~rw13() override;  // 显式声明析构函数
    std::unique_ptr<cpabe> clone() const override;

    void Setup() override;

    void Keygen() override;

    void Encrypt(const std::string& ptx) override;

    std::string Decrypt(const std::string& ctx) override;
};

} // namespace crypto

#endif // CRYPTO_RW13_H