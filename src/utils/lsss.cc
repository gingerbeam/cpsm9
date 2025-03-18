#include "utils/lsss.h"
#include <cstdlib>

namespace utils {

// ExprParser
std::vector<std::string> ExprParser::tokenize(const std::string& input) {
    std::vector<std::string> tokens;
    int n = input.size();
    for (int i = 0; i < n; ) {
        // 跳过空格
        while (i < n && isspace(input[i])) i++;
        if (i >= n) break;

        // 处理括号
        if (input[i] == '(' || input[i] == ')') {
            tokens.push_back(std::string(1, input[i++]));
            continue;
        }

        // 处理关键字 "and" 或 "or"
        if (i + 3 <= n && input[i] == 'a' && input[i+1] == 'n' && input[i+2] == 'd') {
            tokens.push_back("and");
            i += 3;
            continue;
        }
        if (i + 2 <= n && input[i] == 'o' && input[i+1] == 'r') {
            tokens.push_back("or");
            i += 2;
            continue;
        }

        // 处理标识符（允许字母和数字）
        std::string token;
        bool found = false;
        while (i < n && isalnum(input[i])) {
            token += input[i++];
            found = true;
        }
        if (found) {
            tokens.push_back(token);
        } else {
            // 遇到无法处理的字符（如符号），强制递增i
            i++; 
        }
    }
    return tokens;
}

// impossible to exceed expression.size()
int ExprParser::traverse(int nodeIdx, int c, std::vector<int> &pVec) {
    if (nodeIdx >=0) { // is an operator
        Node &node = expression[nodeIdx];
        if (node.op_type == 1) { // OR gate
            return std::max(traverse(node.left, c, pVec), traverse(node.right, c, pVec));
        } else if (node.op_type == 0) { // AND gate
            std::vector<int> lVec(pVec);
            lVec.push_back(1);
            std::vector<int> rVec(0, pVec.size());
            rVec.push_back(-1);
            return std::max(traverse(node.left, c + 1, lVec), traverse(node.right, c + 1, rVec));
        }
    } else { // is leaf node
        // std::cout << "DEBUG - test: vecs[itor_map[nodeIdx]] = pVec;" << std::endl;
        // vecs[itor_map[nodeIdx]] = pVec;
        vecs.push_back(pVec);
        // std::cout << "DEBUG - test: vecs[itor_map[nodeIdx]] = pVec;" << std::endl;
        return c;
    }
}

ExprParser::ExprParser(std::string &input) {
    std::vector<std::string> tokens = tokenize(input);
    
    std::vector<std::string> postfix;
    std::stack<std::string> op_stack;

    std::unordered_map<std::string, int> precedence = {{"and", 2}, {"or", 1}};
    std::unordered_map<std::string, int> associativity = {{"and", 1}, {"or", 1}};

    for (const auto& token : tokens) {
        if (token == "and" || token == "or") {
            while (!op_stack.empty() && op_stack.top() != "(" &&
                (precedence[op_stack.top()] > precedence[token] ||
                (precedence[op_stack.top()] == precedence[token] && associativity[token] == 0))) {
                postfix.push_back(op_stack.top());
                op_stack.pop();
            }
            op_stack.push(token);
        } else if (token == "(") {
            op_stack.push(token);
        } else if (token == ")") {
            while (!op_stack.empty() && op_stack.top() != "(") {
                postfix.push_back(op_stack.top());
                op_stack.pop();
            }
            if (!op_stack.empty() && op_stack.top() == "(") {
                op_stack.pop();
            }
        } else {
            postfix.push_back(token);
        }
    }

    while (!op_stack.empty()) {
        postfix.push_back(op_stack.top());
        op_stack.pop();
    }

    std::stack<int> node_stack;

    for (const auto& token : postfix) {
        if (token == "and" || token == "or") { // is an operator
            int right = node_stack.top();
            node_stack.pop();
            int left = node_stack.top();
            node_stack.pop();
            int op_type = (token == "and") ? 0 : 1;
            int index = expression.size();
            expression.push_back({op_type, left, right});
            node_stack.push(index);
        } else { // is an attribute -> reach a leaf node
            if (atoi_map.find(token) == atoi_map.end()) { // 映射不存在，创建映射
                atoi_map[token] = -static_cast<int>(atoi_map.size()) - 1; // 将属性值映射为负数
                // TODO: 这一堆映射该优化了
                itoa_map[atoi_map[token]] = token;
                itor_map.push_back(atoi_map[token]);
                rtoi_map[itor_map.size() - 1] = atoi_map[token];
            } // 否则 atoi_map[token] 为节点中的映射值
            node_stack.push(atoi_map[token]);
        }
    }

    // Adjust indices for reversed nodes
    for (auto& node : expression) {
        if (node.left >= 0) {
            node.left = expression.size() - 1 - node.left;
        }
        if (node.right >= 0) {
            node.right = expression.size() - 1 - node.right;
        }
    }
    std::reverse(expression.begin(), expression.end());

    leaf_count = atoi_map.size();
    // vecs = new std::vector<int>(leaf_count);
    std::vector<int> iVec = {1};
    tree_depth = traverse(0, 1, iVec);
}

// LSSS
LSSS::LSSS(pairing_t *bp, std::string str) {
    parser = new ExprParser(str);
    l = parser->get_l();
    n = parser->get_n();
    pairing = bp;
    policy.M = std::vector<std::vector<element_t*>>(l, std::vector<element_t*>(n));
    for (int i = 0; i < l; ++i) {
        for (int j = 0; j < n; ++j) {
            policy.M[i][j] = (element_t *)(new element_t);
            element_init_Zr(*(policy.M[i][j]), *pairing);
        }
    }
    policy.rho = std::vector<std::string>(l, "");
    genLSSSPair();
}

LSSS::~LSSS() {
}

void LSSS::genLSSSPair() {
    for (int i = 0; i < l; ++i) {
        for (int j = 0; j < n; ++j) {
            element_set0(*(policy.M[i][j]));
        }
        for (int j = 0; j < parser->vecs[i].size(); ++j) {
            element_set_si(*(policy.M[i][j]), (parser->vecs[i])[j]);
        }
    }
    for (int i = 0; i < parser->get_l(); ++i) {
        policy.rho[i] = parser->itoa_map[parser->rtoi_map[i]];
    }
}

std::vector<element_t*> LSSS::share(element_t *secret) {
    element_t tmp;
    element_init_Zr(tmp, *pairing);

    std::vector<element_t*> vec(n);
    vec[0] = (element_t *)(new element_t);
    element_init_Zr(*(vec[0]), *pairing);
    element_set(*(vec[0]), *secret);
    for (int i = 1; i < n; ++i) {
        vec[i] = (element_t *)(new element_t);
        element_init_Zr(*(vec[i]), *pairing);
        element_random(*(vec[i]));
    }

    std::vector<element_t*> shares(l);
    for (int i = 0; i < l; ++i) {
        shares[i] = (element_t *)(new element_t);
        element_init_Zr(*(shares[i]), *pairing);
        element_set0(*(shares[i]));
    }

    for (int i = 0; i < l; ++i) {
        for (int j = 0; j < n; ++j) {
            element_mul(tmp, *(vec[j]), *(policy.M[i][j]));
            element_add((*shares[i]), (*shares[i]), tmp);
        }
    }
    return shares;
}

void LSSS::solve(int row_n, int col_n, std::vector<element_t*> &omega) {
    element_t tmp;
    element_init_Zr(tmp, *pairing);
    element_t pivot_inv;
    element_init_Zr(pivot_inv, *pairing);

    std::vector<std::vector<element_t*>> aug(row_n, std::vector<element_t*>(col_n + 1));
    // tranpose & augment
    for (int i = 0; i < row_n; ++i) {
        for (int j = 0; j < col_n; ++j) {
            aug[i][j] = (element_t *)(new element_t);
            element_init_Zr(*(aug[i][j]), *pairing);
            element_set(*(aug[i][j]), *(policy.M[S[j]][i]));
        }
        aug[i][col_n] = (element_t *)(new element_t);
        element_init_Zr(*(aug[i][col_n]), *pairing);
        element_set_si(*(aug[i][col_n]), ((i == 0) ? 1 : 0));
    }

    // std::cout << "DEBUG probe solve - augment - OK\n";

    int rank = 0;
    std::vector<int> pivot_cols(row_n, -1);
    for (int col = 0; col < col_n && rank < row_n; ++col) {
        // find pivot row
        int pivot_row = rank;
        for (int row = rank + 1; row < row_n; ++row) {
            if (!element_is0(*(aug[row][col]))) {
                pivot_row = row;
            }
        }
        // is pivot?
        if (element_is0(*(aug[pivot_row][col]))) {
            continue;
        }
        // swap pivot row
        std::swap(aug[rank], aug[pivot_row]);
        element_invert(pivot_inv, *(aug[rank][col]));
        for (int j = col; j <= col_n; ++j) {
            element_mul(*(aug[rank][j]), *(aug[rank][j]), pivot_inv);
        }
        for (int row = 0; row < row_n; ++row) {
            if (row != rank) {
                element_t factor;
                element_init_Zr(factor, *pairing);
                element_set(factor, *(aug[row][col]));
                for (int j = col; j <= col_n; ++j) {
                    element_mul(tmp, *(aug[rank][j]), factor);
                    element_sub(*(aug[row][j]), *(aug[row][j]), tmp);
                }
            }
        }
        // record pivot col
        pivot_cols[rank] = col;
        ++rank;
    }
    // std::cout << "DEBUG probe solve - pivot - OK\n";
    // check for conflicts
    for (int row = rank; row < row_n; ++row) {
        if (!element_is0(*(aug[row][col_n]))) {
            throw std::runtime_error("No solution"); // 无解，返回空
        }
    }
    // std::cout << "DEBUG probe solve - no solution - OK\n";
    // // solution vector
    // std::vector<element_t*> x(col_n + 1);
    // for (int i = 0; i <= col_n; ++i) {
    //     x[i] = (element_t *)(new element_t);
    //     element_init_Zr(*(x[i]), *pairing);
    //     element_set0(*(x[i]));
    // }
    // std::cout << "DEBUG probe solve - solution vector - OK\n";
    // find special solution (reverse)
    for (int row = rank - 1; row >= 0; --row) {
        int col = pivot_cols[row];
        element_t val;
        element_init_Zr(val, *pairing);
        element_set(val, *(aug[row][col_n]));
        for (int j = col + 1; j < col_n; ++j) {
            element_mul(tmp, *(aug[row][j]), *(omega[j]));
            element_sub(val, val, tmp);
        }
        element_set(*(omega[col]), val);
    }
    // std::cout << "DEBUG probe solve - special solution - OK\n";

    // element_clear(tmp);
    // return x;
}

void LSSS::reconstruct(std::vector<std::string> aSet, std::vector<element_t*> shares, element_t *result) {
    element_t tmp;
    element_init_Zr(tmp, *pairing);

    S.clear();
    std::unordered_map<int, int> row_mapping; // 小矩阵行号与原始行号的映射
    // 匹配属性集合，找到 rho(i) 在 aSet 中出现的行号
    for (size_t i = 0; i < l; ++i) {
        if (std::find(aSet.begin(), aSet.end(), (policy.rho)[i]) != aSet.end()) {
            S.push_back(i);
            row_mapping[S.size() - 1] = i; // 记录小矩阵行号与原始行号的映射
        }
    }
    if (S.empty()) {}

    std::vector<element_t*> omega(S.size());
    for (int i = 0; i < S.size(); ++i) {
        omega[i] = (element_t *)(new element_t);
        element_init_Zr(*(omega[i]), *pairing);
    }
    solve(n, S.size(), omega);
    // auto omega = solve(n, S.size());

    // std::cout << "DEBUG probe reconstruct - solve - OK\n";

    for (int i = 0; i < S.size(); ++i) {
        element_mul(tmp, *(shares[row_mapping[i]]), *(omega[i]));
        element_add(*result, *result, tmp);
    }
}

std::unordered_map<int, element_t*> LSSS::retriveOmega(std::vector<std::string> aSet) {
    // std::vector<int> S; // 存储匹配的行号
    std::unordered_map<int, int> row_mapping; // 小矩阵行号与原始行号的映射
    // 匹配属性集合，找到 rho(i) 在 aSet 中出现的行号
    for (size_t i = 0; i < l; ++i) {
        if (std::find(aSet.begin(), aSet.end(), (policy.rho)[i]) != aSet.end()) {
            S.push_back(i);
            row_mapping[S.size() - 1] = i; // 记录小矩阵行号与原始行号的映射
        }
    }
    if (S.empty()) {}

    std::vector<element_t*> omega(S.size());
    for (int i = 0; i < S.size(); ++i) {
        omega[i] = (element_t *)(new element_t);
        element_init_Zr(*(omega[i]), *pairing);
    }
    solve(n, S.size(), omega);
    std::unordered_map<int, element_t*> omega_map;
    for (int i = 0; i < S.size(); ++i) {
        // idx of original rho to S
        omega_map[S[i]] = (omega[i]);
        // omega_map[parser->itoa_map[parser->rtoi_map[row_mapping[i]]]] = (omega[i]);
    }
    return omega_map;
}

}