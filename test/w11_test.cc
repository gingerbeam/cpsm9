#include "crypto/w11.h"  // 确保包含正确的头文件
#include <vector>
#include <iostream>

#include <curve/params.h>

using namespace crypto;

CurveParams curve;

int main() {
    std::vector<std::string> attrs = {"A", "B", "C"};
    std::string policy = "A and B and C";

    crypto::w11 sch(curve.a_param);
    sch.Setup(42);
    element_t m;
    element_init_G1(m, *(sch.getpairing()));
    plaintext ptx = {&m};

    // 使用原型创建新实例
    // for (auto& proto : prototypes) {
    //     auto algorithm = proto->clone();
    //     algorithm->Setup(42, curve.a_param);

    //     element_t m;
        // element_init_G1(m, *(algorithm->get_curve()));
        // algorithm->Setup();
        // algorithm->Keygen();
        // // 测试 Encrypt 和 Decrypt
        // std::string ptx = "Test Plaintext";
        // algorithm->Encrypt(ptx);
        // std::string ctx = "Test Ciphertext";
        // std::string result = algorithm->Decrypt(ctx);
        // std::cout << "Decryption Result: " << result << std::endl;
    // }

    return 0;
}