#include "utils/lsss.h"

namespace utils {
std::vector<std::string> tokenize(const std::string& input) {
    // std::regex token_regex("(and|or|\\w+)");
    // auto tokens_begin = std::sregex_iterator(input.begin(), input.end(), token_regex);
    // auto tokens_end = std::sregex_iterator();
    // std::vector<std::string> tokens;
    // for (std::sregex_iterator i = tokens_begin; i != tokens_end; ++i) {
    //     tokens.push_back(i->str());
    // }
    // return tokens;
    std::vector<std::string> tokens;
    int n = input.size();
    for (int i = 0; i < n; ) {
        while (i < n && isspace(input[i])) i++;
        if (i >= n) break;
        
        if (input[i] == '(' || input[i] == ')') {
            tokens.push_back(std::string(1, input[i++]));
        } else if (i + 3 <= n && input.substr(i, 3) == "and") {
            tokens.push_back("and");
            i += 3;
        } else if (i + 2 <= n && input.substr(i, 2) == "or") {
            tokens.push_back("or");
            i += 2;
        } else {
            // 处理单个字符的操作数（如A/B/C等）
            // TODO: 处理更多操作数，例如字符串
            // tokens.push_back(std::string(1, input[i++]));
            std::string token;
            while (i < n && isalpha(input[i])) {
                token += input[i++];
            }
            tokens.push_back(token);
        }
    }
    return tokens;
}

std::unordered_map<int, std::string> LSSS::parse(std::string& input) {
    auto tokens = tokenize(input);

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
            // 左括号直接入栈
            op_stack.push(token);
        } else if (token == ")") {
            // 遇到右括号，弹出操作符直到左括号
            while (!op_stack.empty() && op_stack.top() != "(") {
                postfix.push_back(op_stack.top());
                op_stack.pop();
            }
            if (!op_stack.empty() && op_stack.top() == "(") {
                op_stack.pop(); // 弹出左括号
            }
        } else {
            // 操作数直接加入后缀表达式
            postfix.push_back(token);
        }
    }

    // 将剩余的操作符加入后缀表达式
    while (!op_stack.empty()) {
        postfix.push_back(op_stack.top());
        op_stack.pop();
    }

    std::unordered_map<std::string, int> var_map;
    std::unordered_map<int, std::string> attr_map;
    // build expression tree
    std::stack<int> node_stack;
    std::stack<std::string> str_node_stack;
    std::vector<Node> nodes;

    for (const auto& token : postfix) {
        if (token == "and" || token == "or") {
            int right = node_stack.top();
            node_stack.pop();
            int left = node_stack.top();
            node_stack.pop();
            int op_type = (token == "and") ? 0 : 1;
            int index = nodes.size();
            nodes.push_back({op_type, left, right});
            node_stack.push(index);
        } else {
            if (var_map.find(token) == var_map.end()) { // 映射不存在，创建映射
                var_map[token] = -static_cast<int>(var_map.size()) - 1; // 将属性值映射为负数
                attr_map[var_map[token]] = token;
            } // 否则 var_map[token] 为节点中的映射值
            node_stack.push(var_map[token]);
        }
    }

    // Adjust indices for reversed nodes
    for (auto& node : nodes) {
        if (node.left >= 0) {
            node.left = nodes.size() - 1 - node.left;
        }
        if (node.right >= 0) {
            node.right = nodes.size() - 1 - node.right;
        }
    }
    std::reverse(nodes.begin(), nodes.end());

    // tree expression
    expression = nodes;
    return attr_map;
}

void LSSS::generateVectors(int nodeIndex, std::vector<int> parentVector, int c,
    std::vector<std::vector<int>>& matrix,
    std::vector<std::string>& mapping,
    const std::vector<LSSS::Node>& exprtree,
    const std::unordered_map<int, std::string>& attr_map) {
    const LSSS::Node& node = exprtree[nodeIndex];

    if (node.op_type == 1) { // OR gate
        if (node.left < 0) { // leaf node & attribute
            matrix.push_back(parentVector);
            mapping.push_back(attr_map.at(node.left)); // 修改：使用 at() 方法
        } else {
            generateVectors(node.left, parentVector, c, matrix, mapping, exprtree, attr_map);
        }
        if (node.right < 0) {
            matrix.push_back(parentVector);
            mapping.push_back(attr_map.at(node.right)); // 修改：使用 at() 方法
        } else { // recursive call
            generateVectors(node.right, parentVector, c, matrix, mapping, exprtree, attr_map);
        }
    } else if (node.op_type == 0) { // AND gate
        // expand parent v to |c|
        while (parentVector.size() < static_cast<size_t>(c)) {
            parentVector.push_back(0);
        }
        // child v
        std::vector<int> vec1 = parentVector;
        vec1.push_back(1);
        std::vector<int> vec0(c, 0);
        vec0.push_back(-1);
        int nctr = c + 1; // counter increment

        if (node.left < 0) {
            matrix.push_back(vec1);
            mapping.push_back(attr_map.at(node.left)); // 修改：使用 at() 方法
        } else { // 子节点递归处理
            generateVectors(node.left, vec1, nctr, matrix, mapping, exprtree, attr_map);
        }
        if (node.right < 0) {
            matrix.push_back(vec0);
            mapping.push_back(attr_map.at(node.right)); // 修改：使用 at() 方法
        } else { // recursive call
            generateVectors(node.right, vec0, nctr, matrix, mapping, exprtree, attr_map);
        }
    }
}

std::pair<std::vector<std::vector<int>>, std::vector<std::string>> LSSS::convertToLSSS(const std::unordered_map<int, std::string>& attr_map) {
    const std::vector<Node> &nodes = expression;
    // 生成向量
    std::vector<std::vector<int>> matrix;
    std::vector<std::string> mapping;
    int c = 1;
    generateVectors(0, {1}, c, matrix, mapping, nodes, attr_map);

    // 填充向量到最大长度
    size_t maxLen = 0;
    for (const auto& vec : matrix) {
        if (vec.size() > maxLen) {
            maxLen = vec.size();
        }
    }
    for (auto& vec : matrix) {
        while (vec.size() < maxLen) {
            vec.push_back(0);
        }
    }

    M = matrix;
    rho = mapping;

    return {matrix, mapping};
}

LSSS::LSSS(std::string policy) {
    std::unordered_map<int, std::string> attr_map = this->parse(policy);
    std::pair<std::vector<std::vector<int>>, std::vector<std::string>> lsss = convertToLSSS(attr_map);
}

LSSS::~LSSS() {

}

void LSSS::share(int secret, int** shares) {
    std::vector<std::vector<int>>& matrix = M;
    int l = matrix.size(); // 矩阵的行数（即向量维度）
    if (l == 0) return; // 处理空矩阵
    int n = matrix[0].size(); // 矩阵的列数（结果向量的维度）

    std::vector<int> vec;
    vec.push_back(secret);
    for (int i = 1; i < n; ++i) {
        vec.push_back(rand() % 100); // 需先调用srand初始化种子
    }

    std::vector<int> result(l, 0); // 初始化结果向量 [[8]]

    *shares = new int[l];
    // std::cout << "DEBUG - shares: ";
    memset(*shares, 0, l * sizeof(int));
    for (int i = 0; i < l; ++i) {
        for (int j = 0; j < n; ++j) {
            (*shares)[i] += vec[j] * matrix[i][j];
        }
        // std::cout << (*shares)[i] << " ";
    }
    // std::cout << std::endl;
}

std::vector<double> find_special_solution(const std::vector<std::vector<int>>& mat) {
    int m = mat.size();
    if (m == 0) return std::vector<double>();
    int n = mat[0].size();

    std::vector<std::vector<double>> aug(m, std::vector<double>(n + 1));
    for (int i = 0; i < m; ++i) {
        for (int j = 0; j < n; ++j) {
            aug[i][j] = mat[i][j];
        }
        aug[i][n] = (i == 0) ? 1.0 : 0.0;
    }

    int rank = 0;
    std::vector<int> pivot_cols(m, -1); // 记录主元列的列号

    for (int col = 0; col < n && rank < m; ++col) {
        // 寻找主元行
        int pivot_row = rank;
        for (int row = rank + 1; row < m; ++row) {
            if (abs(aug[row][col]) > abs(aug[pivot_row][col])) {
                pivot_row = row;
            }
        }

        if (abs(aug[pivot_row][col]) < 1e-9) {
            continue; // 当前列无法选主元，跳过
        }

        // 交换主元行
        swap(aug[rank], aug[pivot_row]);

        // 归一化主元行
        double pivot_val = aug[rank][col];
        for (int j = col; j <= n; ++j) {
            aug[rank][j] /= pivot_val;
        }

        // 消去其他行的当前列
        for (int row = 0; row < m; ++row) {
            if (row != rank) {
                double factor = aug[row][col];
                for (int j = col; j <= n; ++j) {
                    aug[row][j] -= factor * aug[rank][j];
                }
            }
        }

        // 记录主元列
        pivot_cols[rank] = col;
        rank++;
    }

    // 检查是否有矛盾
    for (int row = rank; row < m; ++row) {
        if (abs(aug[row][n]) > 1e-9) {
            return std::vector<double>(); // 无解，返回空
        }
    }

    // 构造解向量
    std::vector<double> x(n, 0.0);

    // 逆序处理主元行
    for (int row = rank - 1; row >= 0; --row) {
        int col = pivot_cols[row];
        double val = aug[row][n];
        // 减去后面的变量的贡献
        for (int j = col + 1; j < n; ++j) {
            val -= aug[row][j] * x[j];
        }
        x[col] = val;
    }

    return x;
}

std::vector<int> compute_omega(const std::vector<std::vector<int>>& mat) {
    int l = mat.size();
    // std::cout << "DEBUG - l: " << l << std::endl;
    if (l == 0) {
        throw std::invalid_argument("Matrix has zero rows.");
    }
    int n = mat[0].size();
    // std::cout << "DEBUG - n: " << n << std::endl;
    if (n == 0) {
        throw std::invalid_argument("Matrix has zero columns.");
    }
    // if (n > l) {
    //     throw std::runtime_error("The number of equations exceeds the number of variables, no solution exists.");
    // }

    // tranpose
    std::vector<std::vector<int>> tmat(n, std::vector<int>(l, 0));
    for (int i = 0; i < n; ++i) {
        for (int k = 0; k < l; ++k) {
            tmat[i][k] = mat[k][i];
        }
    }
    std::vector<double> omega = find_special_solution(tmat);

    // 转换为整数（四舍五入）
    std::vector<int> result(l);
    for (int i = 0; i < l; ++i) {
        result[i] = static_cast<int>(std::round(omega[i]));
    }

    return result;
}

int LSSS::reconstruct(std::vector<std::string> aSet, int *shares) {
    std::vector<int> S; // 存储匹配的行号
    std::unordered_map<int, int> row_mapping; // 小矩阵行号与原始行号的映射

    // 匹配属性集合，找到 rho(i) 在 aSet 中出现的行号
    for (size_t i = 0; i < rho.size(); ++i) {
        if (std::find(aSet.begin(), aSet.end(), rho[i]) != aSet.end()) {
            S.push_back(i);
            row_mapping[S.size() - 1] = i; // 记录小矩阵行号与原始行号的映射
        }
    }

    if (S.empty()) {
        return {};
    }

    // 提取 S 中对应的行组成小矩阵 mat
    std::vector<std::vector<int>> mat(S.size(), std::vector<int>(M[0].size(), 0));
    for (size_t i = 0; i < S.size(); ++i) {
        mat[i] = M[S[i]]; // 提取对应的行
    }

    std::vector<int> omega = compute_omega(mat);

    // inner product
    int res = 0;
    for (int i = 0; i < S.size(); ++i) {
        res += omega[i] * shares[row_mapping[i]];
    }
    return res;
}

}