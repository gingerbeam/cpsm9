#include "crypto/sm9_cp.h"  // 确保包含正确的头文件

#include <vector>
#include <iostream>

using namespace crypto;

int main() {
    // 创建原型对象
    std::vector<std::unique_ptr<cpabe>> prototypes;
    prototypes.emplace_back(std::make_unique<sm9_cp>());

    // 使用原型创建新实例
    for (auto& proto : prototypes) {
        auto algorithm = proto->clone();
        algorithm->Setup();
        algorithm->Keygen();
        // 测试 Encrypt 和 Decrypt
        std::string ptx = "Test Plaintext";
        algorithm->Encrypt(ptx);
        std::string ctx = "Test Ciphertext";
        std::string result = algorithm->Decrypt(ctx);
        std::cout << "Decryption Result: " << result << std::endl;
    }

    return 0;
}