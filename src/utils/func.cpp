#include "utils/func.h"
#include <openssl/sha.h>

void Hm(element_t &m, element_t &res, element_t &tmp_Zp, element_t &g) {
    // 计算SHA-256哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned char bytes1[element_length_in_bytes(m)];
    element_to_bytes(bytes1, m);
    SHA256_Update(&sha256, bytes1, sizeof(bytes1));
    SHA256_Final(hash, &sha256);
    element_from_hash(res, hash, SHA256_DIGEST_LENGTH);
}

void Hgsm(element_t &gs, element_t &m, element_t &res, element_t &tmp_Zp, element_t &g) {
    // 计算SHA-256哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned char bytes1[element_length_in_bytes(gs)];
    element_to_bytes(bytes1, gs);
    SHA256_Update(&sha256, bytes1, sizeof(bytes1));
    unsigned char bytes2[element_length_in_bytes(m)];
    element_to_bytes(bytes2, m);
    SHA256_Update(&sha256, bytes2, sizeof(bytes2));
    SHA256_Final(hash, &sha256);
    element_from_hash(res, hash, SHA256_DIGEST_LENGTH);
}

int CountSize(element_t &t) {
    return element_length_in_bytes(t);
}