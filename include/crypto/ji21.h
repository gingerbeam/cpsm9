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
};

struct master_secretkey {
    element_t s;
    element_t t;
};

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

ji21();

static void ji21_setup(public_parameter* pub, master_secretkey* msk);

static ji21Prv* ji21_keygen(public_parameter* pub, master_secretkey* msk, const std::vector<std::string>& attrs);

static ji21Cph* ji21_enc(public_parameter* pub, const std::string& policy_str, element_t m);

static ji21ElementBoolean* ji21_dec(public_parameter* pub, ji21Prv* prv, ji21Cph* cph);
};

}

#endif