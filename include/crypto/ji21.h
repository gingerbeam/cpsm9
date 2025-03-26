#ifndef UTILS_TREE_H
#define UTILS_TREE_H

#include <string>
#include <iostream>
#include <vector>
#include <unordered_map>

#include <pbc/pbc.h>

namespace crypto {
void string_to_element(element_t& element, const std::string& str);
void element_to_string(element_t& element, std::string& str);
void element_from_string(element_t h, const std::string& s);

class ji21 {
private:
element_t debug_r1;
element_t debug_r2;
element_t debug_s;
element_t debug_gt1;
element_t debug_gt2;
public:
struct plaintext {
    element_t message;
};

struct public_parameter {
    pairing_t pairing;
    element_t p1;
    element_t p2;
    element_t pk1;
    element_t pk2;
    element_t HN;
} pp;

struct master_secretkey {
    element_t s;
    element_t t;
} msk;

struct attribute_key {
    std::string attr;    // 属性名
    element_t k1;         // D_j =  ∈ G_2
    element_t k2;        // D_j' = g^r_j ∈ G_1
};

struct ji21Prv {
    element_t k;         // D = g^((α + r) / β)
    std::vector<attribute_key*> comps; // 属性组件列表
};

struct ji21Polynomial {
    int deg;                        // 多项式的度
    std::vector<element_s*> coef;   // 多项式系数
};

struct ji21Policy {
    int k;                // 阈值 k
    std::string attr;     // 属性名（叶子节点）
    ji21Polynomial* q;  // 多项式 q_x
    std::vector<ji21Policy*> children; // 子节点
    element_t c;          // 密文CT中C_y = g^{q_y(0)} ∈ G_0
    element_t cp;         // 密文CT中C_y' = H(att(y))^{q_y(0)} ∈ G_0
    bool satisfiable;     // 用于解密时是否满足条件
    std::vector<int> satl;// 满足条件的子节点索引列表: 从1开始...
};

struct ji21Cph {
    element_t c1; // c1 = (p1^HN pk1)^r1
    element_t c2; // c2 = M e(p1, p2)^{s r1}
    ji21Policy* p;  // 访问策略的根节点
};

struct ji21ElementBoolean {
    element_t e;  // 解密结果
    bool b;       // 解密成功标志
};

ji21(std::string &param);

ji21Prv* ji21_keygen(const std::vector<std::string>& attrs);

ji21Cph* ji21_enc(const std::string& policy_str, plaintext *ptx);

ji21ElementBoolean* ji21_dec(ji21Prv* prv, ji21Cph* cph);

ji21Polynomial* rand_poly(int deg, element_t zero_val);
void fill_policy(ji21::ji21Policy* p, element_t e);
void decrypt_node_with_lagrange(element_t r, ji21Policy* p, ji21Prv* prv, ji21Cph* cph);
void lagrange_coefficient(element_t coef, const std::vector<int>& satl, int i);

// encapsulate message
void Encaps(int message, plaintext *ptx) {
    element_init_GT(ptx->message, pp.pairing);
    element_set_si(ptx->message, message);
}

void RandomEncaps(plaintext *ptx) {
    element_init_GT(ptx->message, pp.pairing);
    element_random(ptx->message);
}
};
}

#endif