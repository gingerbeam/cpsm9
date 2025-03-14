#ifndef CRYPTO_SM9_CP_H
#define CRYPTO_SM9_CP_H

#include <memory>
#include <string>
#include "crypto/cpabe.h"

namespace crypto {

class sm9_cp : public cpabe {
public:
    ~sm9_cp() override;  // 显式声明析构函数
    std::unique_ptr<cpabe> clone() const override;

    void Setup() override;

    void Keygen() override;

    void Encrypt(const std::string& ptx) override;

    std::string Decrypt(const std::string& ctx) override;
};

} // namespace crypto

#endif // CRYPTO_SM9_CP_H