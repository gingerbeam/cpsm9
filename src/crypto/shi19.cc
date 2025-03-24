#include "crypto/shi19.h"

namespace crypto {

std::string shi19::set_to_id(std::vector<std::string> &attrs) {
    std::string result;
    for (const auto& user : user_set) {
        if (std::find(attrs.begin(), attrs.end(), user) != attrs.end()) {
            result += '1';
        } else {
            result += '0';
        }
    }
    return result;
}

shi19::shi19(std::string &param, std::vector<std::string> U) : besm9(param, U) {

}

void shi19::shi19Keygen(std::vector<std::string> &attrs, secretkey *sk) {
    auto id = set_to_id(attrs);
    kemsm9::Keygen(id, sk);
}

void shi19::shi19Encrypt(plaintext &ptx, std::vector<std::vector<std::string>> &as, abe_ciphertext *ctx) {
    std::vector<std::string> ids(as.size());
    for (int i = 0; i < as.size(); ++i) {
        auto id = set_to_id(as[i]);
        ids[i] = id;
    }
    besm9::BEncrypt(ptx, ids, ctx);
}

void shi19::shi19Decrypt(abe_ciphertext *ctxs, std::vector<std::string> &attrs, secretkey *sk, plaintext *ptx) {
    auto id = set_to_id(attrs);
    besm9::BDecrypt(ctxs, sk, ptx);
}

}