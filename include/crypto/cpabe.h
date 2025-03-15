#ifndef CP_ABE_H
#define CP_ABE_H

#include <pbc/pbc.h>
#include <memory>

#include "utils/lsss.h"

namespace crypto {

class pp{
    int len;
    element_t* pplist;
};

class msk{
    int len;
    element_t* msklist;
};

class skey{
    int len;
    element_t* sklist;
};

class plaintext{
    int len;
    element_t* ptxlist;
};

class ciphertext{
    int len;
    element_t* ctxlist;
};

class cpabe {
public:
    virtual ~cpabe() = default;

    // 原型模式核心方法
    virtual std::unique_ptr<cpabe> clone() const = 0;

    // 算法接口
    virtual void Setup() = 0;
    virtual void Keygen() = 0;
    virtual void Encrypt(const std::string& ptx) = 0;
    virtual std::string Decrypt(const std::string& ctx) = 0;

protected:
    // 保护拷贝构造函数以实现正确克隆
    cpabe() = default;
    cpabe(const cpabe&) = default;
    cpabe& operator=(const cpabe&) = default;
};

} // namespace crypto

#endif // CRYPTO_INTERFACE_HPP