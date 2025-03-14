#include "utils/lsss.h"

std::vector<std::string> tokenize(const std::string& input) {
    std::regex token_regex("(and|or|\\w+)");
    auto tokens_begin = std::sregex_iterator(input.begin(), input.end(), token_regex);
    auto tokens_end = std::sregex_iterator();
    std::vector<std::string> tokens;
    for (std::sregex_iterator i = tokens_begin; i != tokens_end; ++i) {
        tokens.push_back(i->str());
    }
    return tokens;
}

std::vector<std::string> infix_to_postfix(const std::vector<std::string>& tokens) {
    std::vector<std::string> postfix;
    std::stack<std::string> op_stack;

    for (const auto& token : tokens) {
        if (token == "and" || token == "or") {
            while (!op_stack.empty() && (
                precedence[op_stack.top()] > precedence[token] ||
                (precedence[op_stack.top()] == precedence[token] && associativity[token] == LEFT_ASSOC)
            )) {
                postfix.push_back(op_stack.top());
                op_stack.pop();
            }
            op_stack.push(token);
        } else {
            postfix.push_back(token);
        }
    }

    while (!op_stack.empty()) {
        postfix.push_back(op_stack.top());
        op_stack.pop();
    }

    return postfix;
}

void ExpressionParser::build_expression_tree(const std::vector<std::string>& postfix, std::unordered_map<std::string, int>& var_map) {
    std::stack<int> node_stack;
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
            if (var_map.find(token) == var_map.end()) {
                var_map[token] = -static_cast<int>(var_map.size()) - 1;
            }
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

    // return nodes;
    expression = nodes;
}

std::vector<std::vector<int>> ExpressionParser::parse(std::string input) {
    auto tokens = tokenize(input);
    auto postfix = infix_to_postfix(tokens);
    std::unordered_map<std::string, int> var_map;
    build_expression_tree(postfix, var_map);
    std::vector<std::vector<int>> res;
    for (const auto& node : expression) {
        std::vector<int> temp;
        temp.push_back(node.op_type);
        temp.push_back(node.left);
        temp.push_back(node.right);
        res.push_back(temp);
    }
    return res;
}

void generateVectors(int nodeIndex, std::vector<int> parentVector, int& c,
    std::vector<std::vector<int>>& matrix,
    std::vector<std::string>& mapping,
    const std::vector<Node>& nodes) {
    const Node& node = nodes[nodeIndex];

    if (node.op_type == 1) { // OR gate
        if (node.left < 0) { // leaf node
            matrix.push_back(parentVector);
            mapping.push_back(std::string(1, static_cast<char>('A' - 1 - node.left)));
        } else {
            generateVectors(node.left, parentVector, c, matrix, mapping, nodes);
        }
        if (node.right < 0) {
            matrix.push_back(parentVector);
            mapping.push_back(std::string(1, static_cast<char>('A' - 1 - node.right)));
        } else { // 子节点递归处理
            generateVectors(node.right, parentVector, c, matrix, mapping, nodes);
        }
    } else if (node.op_type == 0) { // AND gate
        // 父向量扩展到长度c
        while (parentVector.size() < static_cast<size_t>(c)) {
            parentVector.push_back(0);
        }
        // 生成子向量
        std::vector<int> vec1 = parentVector;
        vec1.push_back(1);
        std::vector<int> vec0(c, 0);
        vec0.push_back(-1);
        c++; // 递增c

        // 处理子节点
        int child = node.left;
        if (child < 0) { // 叶子节点
            matrix.push_back(vec1);
            mapping.push_back(std::string(1, static_cast<char>('A' - 1 -child)));
        } else { // 子节点递归处理
            generateVectors(child, vec1, c, matrix, mapping, nodes);
        }

        child = node.right;
        if (child < 0) { // 叶子节点
            matrix.push_back(vec0);
            mapping.push_back(std::string(1, static_cast<char>('A' - 1 -child)));
        } else { // 子节点递归处理
            generateVectors(child, vec0, c, matrix, mapping, nodes);
        }
    }
}

std::pair<std::vector<std::vector<int>>, std::vector<std::string>> ExpressionParser::convertToLSSS() {
    const std::vector<Node> &nodes = expression;
    // 生成向量
    std::vector<std::vector<int>> matrix;
    std::vector<std::string> mapping;
    int c = 1;
    generateVectors(0, {1}, c, matrix, mapping, nodes);

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

void ExpressionParser::share(int secret) {
    std::vector<std::vector<int>>& matrix = M;
    int l = matrix.size(); // 矩阵的行数（即向量维度）
    if (l == 0) return; // 处理空矩阵 [[7]]
    int n = matrix[0].size(); // 矩阵的列数（结果向量的维度）

    std::vector<int> vec;
    vec.push_back(secret);
    for (int i = 1; i < n; ++i) {
        vec.push_back(rand() % 100); // 需先调用srand初始化种子
    }

    std::vector<int> result(l, 0); // 初始化结果向量 [[8]]
    
    for (int j = 0; j < l; ++j) {
        for (int i = 0; i < n; ++i) {
            result[j] += vec[i] * matrix[j][i];
        }
    }
    
    // return result;
    lambda = result;
}

std::vector<int> compute_omega(const std::vector<std::vector<int>>& mat) {
    int l = mat.size();
    if (l == 0) {
        throw std::invalid_argument("Matrix has zero rows.");
    }
    int n = mat[0].size();
    if (n == 0) {
        throw std::invalid_argument("Matrix has zero columns.");
    }
    if (n > l) {
        throw std::runtime_error("The number of equations exceeds the number of variables, no solution exists.");
    }

    // 构造系数矩阵 M (n行 l列)
    std::vector<std::vector<double>> M(n, std::vector<double>(l, 0.0));
    for (int i = 0; i < n; ++i) {
        for (int k = 0; k < l; ++k) {
            M[i][k] = mat[k][i];
        }
    }

    // 构造右侧向量 b
    std::vector<double> b(n, 0.0);
    b[0] = 1.0;

    // 构造增广矩阵
    std::vector<std::vector<double>> augmented(n, std::vector<double>(l + 1, 0.0));
    for (int i = 0; i < n; ++i) {
        for (int k = 0; k < l; ++k) {
            augmented[i][k] = M[i][k];
        }
        augmented[i][l] = b[i];
    }

    // 高斯消元法
    for (int col = 0; col < n; ++col) {
        // 寻找主元
        int pivot = col;
        for (int row = col + 1; row < n; ++row) {
            if (std::abs(augmented[row][col]) > std::abs(augmented[pivot][col])) {
                pivot = row;
            }
        }
        std::swap(augmented[col], augmented[pivot]);

        // 主元为零，无解
        if (std::abs(augmented[col][col]) < 1e-9) {
            throw std::runtime_error("The system is singular, no solution exists.");
        }

        // 消元
        for (int row = col + 1; row < n; ++row) {
            double factor = augmented[row][col] / augmented[col][col];
            for (int c = col; c <= l; ++c) {
                augmented[row][c] -= factor * augmented[col][c];
            }
        }
    }

    // 回代求解
    std::vector<double> omega(l, 0.0);
    for (int row = n - 1; row >= 0; --row) {
        omega[row] = augmented[row][l];
        for (int c = row + 1; c < l; ++c) {
            omega[row] -= augmented[row][c] * omega[c];
        }
        omega[row] /= augmented[row][row];
    }

    // 转换为整数（四舍五入）
    std::vector<int> result(l);
    for (int i = 0; i < l; ++i) {
        result[i] = static_cast<int>(std::round(omega[i]));
    }

    return result;
}

int ExpressionParser::reconstruct(std::vector<std::string> aSet) {
    std::vector<int> S; // 存储匹配的行号
    std::unordered_map<int, int> row_mapping; // 小矩阵行号与原始行号的映射

    // 1. 匹配属性集合，找到 rho(i) 在 aSet 中出现的行号
    for (size_t i = 0; i < rho.size(); ++i) {
        if (std::find(aSet.begin(), aSet.end(), rho[i]) != aSet.end()) {
            S.push_back(i);
            row_mapping[S.size() - 1] = i; // 记录小矩阵行号与原始行号的映射
        }
    }

    if (S.empty()) {
        // 如果没有匹配的行，返回空向量
        return {};
    }

    // 2. 构造小矩阵 mat
    std::vector<std::vector<int>> mat(S.size(), std::vector<int>(M[0].size(), 0));
    for (size_t i = 0; i < S.size(); ++i) {
        mat[i] = M[S[i]]; // 提取对应的行
    }

    std::vector<int> omega = compute_omega(mat);
    int res = 0;
    for (int i = 0; i < S.size(); ++i) {
        res += omega[i] * lambda[row_mapping[i]];
    }
    return res;
}
