#include <openssl/sha.h>
#include <iostream>
#include <sstream>
#include <stack>
#include <map>
#include <vector>
#include <cstring>
#include <algorithm> // find
#include <sstream> 

#include "crypto/ji21.h"

#include <curve/params.h>

namespace crypto {
void Hash(element_t &m, element_t &res) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned char bytes1[element_length_in_bytes(m)];
    element_to_bytes(bytes1, m);
    SHA256_Update(&sha256, bytes1, sizeof(bytes1));
    SHA256_Final(hash, &sha256);
    element_from_hash(res, hash, SHA256_DIGEST_LENGTH);
}

void string_to_element(element_t& element, const std::string& str) {
    int len = str.size();
    std::vector<unsigned char> buffer(2048, 0);
    memcpy(buffer.data(), str.c_str(), len);
    element_from_bytes(element, buffer.data());
}
void element_to_string(element_t& element, std::string& str) {
    int length = element_length_in_bytes(element);
    std::vector<unsigned char> buffer(length);
    element_to_bytes(buffer.data(), element);
    auto pos = std::find(buffer.begin(), buffer.end(), 0);
    str.assign(reinterpret_cast<char*>(buffer.data()), pos != buffer.end() ? pos - buffer.begin() : length);
}
void element_from_string(element_t h, const std::string& s) {
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(s.c_str()), s.length(), digest);
    element_from_hash(h, digest, SHA_DIGEST_LENGTH);
}

void HtoZ(std::string &m, element_t &res) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    const char *bytes = m.data();
    SHA256_Update(&sha256, bytes, m.size());
    SHA256_Final(hash, &sha256);
    element_from_hash(res, hash, SHA256_DIGEST_LENGTH);
}

ji21::ji21(std::string &param) {
    // init pairing
    pbc_param_t par;
    pbc_param_init_set_str(par, param.c_str());
    pairing_init_pbc_param(pp.pairing, par);
    // init msk
    element_init_Zr(msk.alpha, pp.pairing);
    element_random(msk.alpha);
    // element_init_Zr(debug_alpha, pp.pairing); // debug
    // element_set(debug_alpha, msk.alpha);
    element_init_Zr(msk.beta, pp.pairing);
    element_random(msk.beta);
    // public parameters
    // generators
    element_init_G1(pp.p1, pp.pairing);
    element_random(pp.p1);
    element_init_G2(pp.p2, pp.pairing);
    element_random(pp.p2);
    // pk1 & pk2
    element_init_G1(pp.pk1, pp.pairing);
    element_pow_zn(pp.pk1, pp.p1, msk.alpha);
    element_init_G1(pp.pk2, pp.pairing);
    element_pow_zn(pp.pk2, pp.p1, msk.beta);
    // generate HN
    element_init_Zr(pp.HN, pp.pairing);
    element_t N;
    element_init_Zr(N, pp.pairing);
    element_random(N);
    Hash(N, pp.HN);
}

ji21::ji21Prv* ji21::ji21_keygen(std::vector<std::string>& attrs) {
    ji21Prv* prv = new ji21Prv();
    // randomness for keygen
    element_t r;
    element_init_Zr(r, pp.pairing);
    element_random(r);
    // element_init_Zr(debug_r, pp.pairing);
    // element_set(debug_r, r);
    // compute k = p2^{alpha + r / HN + alpha}
    element_t deno;
    element_init_Zr(deno, pp.pairing);
    element_add(deno, pp.HN, msk.alpha); // HN + alpha
    element_invert(deno, deno); // 1 / (HN + alpha)
    element_t nume;
    element_init_Zr(nume, pp.pairing);
    element_add(nume, msk.alpha, r); // alpha + r
    element_mul(nume, nume, deno); // (alpha + r) / (HN + alpha)
    element_init_G2(prv->k, pp.pairing);
    element_pow_zn(prv->k, pp.p2, nume);
    // // free temporary variables
    // element_clear(deno);
    // element_clear(nume);
    // for every attribute, compute k1 and k2
    for (std::string& attr : attrs) {
        attribute_key* comp = new attribute_key();
        comp->attr = attr;
        // random rj
        element_t rj;
        element_init_Zr(rj, pp.pairing);
        element_random(rj);
        // k1 = ((p2)^r2 * (h1j)^rj)^{1/t}
        element_t h1j;
        element_init_G2(h1j, pp.pairing);
        HtoZ(attr, h1j);
        // element_from_string(h1j, attr);
        element_pow_zn(h1j, h1j, rj);
        element_init_G2(comp->k1, pp.pairing);
        element_pow_zn(comp->k1, pp.p2, r);
        element_mul(comp->k1, comp->k1, h1j);
        element_t exp;
        element_init_Zr(exp, pp.pairing);
        element_invert(exp, msk.beta);
        element_pow_zn(comp->k1, comp->k1, exp);
        // k2 = p1^rj
        element_init_G1(comp->k2, pp.pairing);
        element_pow_zn(comp->k2, pp.p1, rj);
        prv->comps.push_back(comp);
    }
    return prv;
}

ji21::ji21Policy* base_node(int k, const std::string& s) {
    ji21::ji21Policy* p = new ji21::ji21Policy();
    p->k = k;
    p->attr = s;
    p->q = nullptr;
    p->satisfiable = false;
    return p;
}

std::vector<std::string> convertInfixToPostfix(const std::string& infix) {
    std::vector<std::string> tokens;
    std::istringstream iss(infix);
    std::string token;
    while (iss >> token) {
        tokens.push_back(token);
    }

    std::stack<std::string> opStack;
    std::vector<std::string> output;

    auto precedence = [](const std::string& op) -> int {
        if (op == "or") return 1;
        else if (op == "and") return 2;
        return 0;
    };

    for (const auto& token : tokens) {
        if (token == "(") {
            opStack.push(token);
        } else if (token == ")") {
            while (!opStack.empty() && opStack.top() != "(") {
                output.push_back(opStack.top());
                opStack.pop();
            }
            if (opStack.empty() || opStack.top() != "(") {
                throw std::runtime_error("Mismatched parentheses");
            }
            opStack.pop();
        } else if (token == "or" || token == "and") {
            while (!opStack.empty() && opStack.top() != "(" &&
                   precedence(opStack.top()) >= precedence(token)) {
                output.push_back(opStack.top());
                opStack.pop();
            }
            opStack.push(token);
        } else {
            output.push_back(token);
        }
    }

    while (!opStack.empty()) {
        if (opStack.top() == "(" || opStack.top() == ")") {
            throw std::runtime_error("Mismatched parentheses");
        }
        output.push_back(opStack.top());
        opStack.pop();
    }

    return output;
}

ji21::ji21Policy* parse_policy_postfix(const std::string& s) {
    std::vector<std::string> tokens = convertInfixToPostfix(s);
    std::vector<ji21::ji21Policy*> stack;

    for (const auto& tok : tokens) {
        if (tok == "and" || tok == "or") {
            int k, n;
            if (tok == "and") {
                k = 2;
                n = 2;
            } else if (tok == "or") {
                k = 1;
                n = 2;
            }
            if (stack.size() < n) {
                throw std::runtime_error("Insufficient nodes in stack to pop required number of children");
            }
            ji21::ji21Policy* node = base_node(k, "");
            node->children.resize(n);
            for (int i = n - 1; i >= 0; --i) {
                node->children[i] = stack.back();
                stack.pop_back();
            }
            stack.push_back(node);
        } else {
            stack.push_back(base_node(1, tok));
        }
    }
    if (stack.size() != 1) {
        throw std::runtime_error("Invalid policy string format");
    }
    return stack.back();
}

ji21::ji21Polynomial* ji21::rand_poly(int deg, element_t zero_val) {
    ji21::ji21Polynomial* q = new ji21::ji21Polynomial();
    q->deg = deg;
    q->coef.resize(deg + 1);
    for (int i = 0; i <= deg; i++) {
        q->coef[i] = (element_s*)malloc(sizeof(element_s));
        element_init_same_as(q->coef[i], zero_val);
    }
    // 设置多项式在 x=0 处的值为 zero_val，即常数项，也即s=qx(0)
    element_set(q->coef[0], zero_val);
    // 为多项式的其他系数赋值
    for (int i = 1; i <= deg; i++) {
        element_random(q->coef[i]);
        // element_set_si(q->coef[i], 2);
    }
    return q;
}

void eval_poly(element_t r, ji21::ji21Polynomial* q, element_t x) {
    element_t sum, exp, term;
    // 初始化临时变量 sum，用于累加多项式求和值，与 r 类型相同
    element_init_same_as(sum, r);
    // 初始化临时变量 term，用于存储每一项的计算结果，与 r 类型相同
    element_init_same_as(term, r);
    // 初始化临时变量 exp，用于计算 x 的幂次，与 x 类型相同
    element_init_same_as(exp, x);
    // sum = 0，初始化求和值为零
    element_set0(sum);
    // exp = 1，初始化 x 的指数次幂为 1（即 x^0）
    element_set1(exp);
    // 遍历多项式的所有系数，计算 sum = ∑ (q->coef[i] * x^i)
    // 例如：f(x) = ax^2+bx+c，一个三个系数，下面循环执行三次；第一次结束sum = c, exp = x; 第二次结束sum = c + bx, exp = x^2; 第三次结束sum = c + bx + ax^2, exp = x^3;
    for (int i = 0; i <= q->deg; ++i) {
        // term = q->coef[i] * exp，计算当前项的值
        element_mul(term, q->coef[i], exp);
        // sum += term，将当前项的值累加到总和中
        element_add(sum, sum, term);
        // exp *= x，更新 exp 为 x 的下一个幂次（即 x^{i+1}）
        element_mul(exp, exp, x);
    }
    // 将计算得到的多项式值 sum 赋值给结果变量 r，返回的结果变量r
    element_set(r, sum);
}

void ji21::fill_policy(ji21::ji21Policy* p, element_t sec) {
    // e is the secret to share
    p->q = rand_poly(p->k - 1, sec);  // deg = k-1, q(0) = sec
    if (p->children.empty()) {      // leaf node
        element_init_G1(p->c, pp.pairing);
        element_init_G2(p->cp, pp.pairing);
        // 将属性字符串映射为群元素 h_attr = H(attr)
        element_t h_attr;
        element_init_G2(h_attr, pp.pairing);
        HtoZ(p->attr, h_attr);
        // element_from_string(h_attr, p->attr);
        // 计算加密组件
        // c = pk2^{q(0)} = p1^{beta q(0)}
        element_pow_zn(p->c, pp.pk2, p->q->coef[0]);
        // cp = H(attr)^{q(0)}
        element_pow_zn(p->cp, h_attr, p->q->coef[0]);
        // 清理临时元素 h_attr
        element_clear(h_attr);
    } else { // boolean gate
        // 初始化临时元素 index，用于表示子节点的序号
        element_t index;
        element_init_Zr(index, pp.pairing);
        // 遍历子节点
        for (size_t i = 0; i < p->children.size(); ++i) {
            // 设置 index = i + 1，因为子节点序号从 1 开始
            element_set_si(index, i + 1);
            // 初始化临时元素 q_y0，用于存储多项式在子节点序号处的值 q(i+1)
            element_t q_y0;
            element_init_Zr(q_y0, pp.pairing);
            // 计算多项式 q 在 index 处的值，即 f(x) = q_y0(父节点的f(x)值为子节点的秘密值) = q(index)
            eval_poly(q_y0, p->q, index);
            // 递归调用 fill_policy，填充子节点，传递 q_y0 作为新的 e 值
            fill_policy(p->children[i], q_y0);
            // 清理临时元素 q_y0
            element_clear(q_y0);
        }
        // 清理临时元素 index
        element_clear(index);
    }
}

ji21::ji21Cph* ji21::ji21_enc(const std::string& policy_str, plaintext *ptx) {
    ji21Cph* cph = new ji21Cph();
    // random exponent
    element_t s;
    element_init_Zr(s, pp.pairing);
    element_random(s); 
    // element_init_Zr(debug_s, pp.pairing);
    // element_set(debug_s, s);
    // c_y & c'_y
    cph->p = parse_policy_postfix(policy_str); // parse policy into access tree
    fill_policy(cph->p, s); // set root secret to s & share
    // c1
    element_init_G1(cph->c1, pp.pairing);
    element_pow_zn(cph->c1, pp.p1, pp.HN);
    element_mul(cph->c1, cph->c1, pp.pk1);
    element_pow_zn(cph->c1, cph->c1, s);
    // c2
    element_init_GT(cph->c2, pp.pairing);
    element_pairing(cph->c2, pp.pk1, pp.p2);
    element_pow_zn(cph->c2, cph->c2, s);
    element_mul(cph->c2, cph->c2, ptx->message);
    // free
    element_clear(s);
    return cph;
}

bool check_sat(ji21::ji21Policy* p, const std::vector<std::string>& attrs) {
    if (p->children.empty()) { // check if leaf node attribute is inside user attrs
        p->satisfiable = std::find(attrs.begin(), attrs.end(), p->attr) != attrs.end();
    } else {
        int satisfied = 0;           // 统计满足条件的子节点数量
        p->satl.clear();             // 清空满足条件的子节点索引列表
        // 遍历所有子节点，递归检查每个子节点是否满足条件
        for (size_t i = 0; i < p->children.size(); ++i) {
            if (check_sat(p->children[i], attrs)) {
                satisfied++;                // 如果子节点满足条件，增加计数
                p->satl.push_back(i + 1);   // 记录满足条件的子节点索引，索引从 1 开始计数
            }
        }
        // 根据阈值 k，判断当前节点是否满足条件
        // 如果满足条件的子节点数量不少于阈值 k，则当前节点满足
        p->satisfiable = (satisfied >= p->k);
    }
    // 返回当前节点的 satisfiable 状态
    return p->satisfiable;
}

void ji21::lagrange_coefficient(element_t coef, const std::vector<int>& satl, int i) {
    element_t num, denom; // 分别用于存储分子和分母的中间计算结果
    element_init_Zr(num, pp.pairing);   // 初始化分子 num 为整数域元素
    element_init_Zr(denom, pp.pairing); // 初始化分母 denom 为整数域元素
    element_set1(num);    // num = 1，初始化分子为 1
    element_set1(denom);  // denom = 1，初始化分母为 1

    // 计算拉格朗日系数 λ_i = ∏_{j ≠ i} (-j) / (i - j)
    for (int j : satl) {
        if (j == i) {
            continue;  // 跳过当前节点索引 i
        }
        element_t tmp; // 临时变量用于存储中间结果
        element_init_Zr(tmp, pp.pairing);

        // 计算分子部分 num *= -j
        element_set_si(tmp, -j);          // tmp = -j
        element_mul(num, num, tmp);       // num = num * tmp

        // 计算分母部分 denom *= (i - j)
        element_set_si(tmp, i - j);       // tmp = i - j
        element_mul(denom, denom, tmp);   // denom = denom * tmp

        element_clear(tmp); // 清理临时变量 tmp
    }

    // 计算 denom 的逆元
    element_invert(denom, denom);  // denom = 1 / denom
    // 计算拉格朗日系数 coef = num * denom
    element_mul(coef, num, denom); // coef = num * denom

    // 清理分子和分母的中间结果
    element_clear(num);
    element_clear(denom);
}

void ji21::decrypt_node_with_lagrange(element_t r, ji21Policy* p, ji21Prv* prv, ji21Cph* cph) {
    if (p->children.empty()) { // leaf node
        for (auto& comp : prv->comps) {
            if (comp->attr == p->attr) {  // 找到用户私钥对应的属性密文
                element_t e1, e2;
                element_init_GT(e1, pp.pairing);
                element_init_GT(e2, pp.pairing);
                // e1 = e(C_y, k1)
                element_pairing(e1, p->c, comp->k1);
                // e2 = e(k2, C'_y)
                element_pairing(e2, comp->k2, p->cp);
                element_invert(e2, e2);
                // r = e1 * e2 = e(C_y, k1) / e(k2, C'_y)
                element_mul(r, e1, e2);
                break;
            }
        }
    } else { // non-leaf
        element_t Fx, t;
        // 初始化 Fx，用于累积子节点的解密结果
        element_init_GT(Fx, pp.pairing);
        element_set1(Fx);  // 初始化 Fx 为 1
        // 初始化 t，用于存储拉格朗日系数
        element_init_Zr(t, pp.pairing);
        // 遍历满足条件的子节点索引列表 p->satl
        for (int i : p->satl) {
            element_t share;
            // 初始化 share，用于存储子节点的解密结果
            element_init_GT(share, pp.pairing);
            // 递归解密子节点，注意子节点数组从 0 开始，而 satl 索引从 1 开始
            decrypt_node_with_lagrange(share, p->children[i - 1], prv, cph);
            // 计算拉格朗日系数 t = λ_i
            lagrange_coefficient(t, p->satl, i);
            // 计算 share = share^{λ_i}
            element_pow_zn(share, share, t);
            // 累积计算 Fx = Fx * share
            element_mul(Fx, Fx, share);
            // 清理临时元素 share
            element_clear(share);
        }
        // 将累积结果 Fx 赋值给输出参数 r
        element_set(r, Fx);
    }
}

ji21::ji21ElementBoolean* ji21::ji21_dec(ji21Prv* prv, ji21Cph* cph) {
    ji21ElementBoolean* result = new ji21ElementBoolean();    
    // 提取用户私钥中的属性列表，存入 attrs
    std::vector<std::string> attrs;    // 从私钥中提取用户属性集
    for (size_t i = 0; i < prv->comps.size(); ++i) {
        attrs.push_back(prv->comps[i]->attr);  // 提取每个组件的属性
    }
    // check if attrs is a satisfied set
    if (!check_sat(cph->p, attrs)) {
        throw std::runtime_error("ji21_dec: attrs is not a satisfied set");
        result->b = false;
        return result;
    }
    // recursively decrypt e(p1, p2)^{r s}
    element_t tmp_deno;
    element_init_GT(tmp_deno, pp.pairing);
    element_set1(tmp_deno);
    // recursively call
    decrypt_node_with_lagrange(tmp_deno, cph->p, prv, cph); // bug here
    // // debug: if tmp_deno = e(p1, p2)^{ r2}
    // element_init_GT(debug_gt1, pp.pairing);
    // element_pairing(debug_gt1, pp.p1, pp.p2);
    // element_pow_zn(debug_gt1, debug_gt1, debug_r);
    // element_pow_zn(debug_gt1, debug_gt1, debug_s);
    // if (!element_cmp(debug_gt1, tmp_deno)) printf("SAME\n");
    // else printf("DIFF\n");
    // e(c1, k)
    element_t B;
    element_init_GT(B, pp.pairing);
    element_pairing(B, cph->c1, prv->k);
    // B = e(c1, k) / e(p1, p2)^{r1 r2} = e(p1, p2)^{r1 s}
    element_div(B, B, tmp_deno);
    // M = c2 / B
    element_init_GT(result->e, pp.pairing);
    element_div(result->e, cph->c2, B);
    result->b = true; // 解密成功
    return result;
}

}