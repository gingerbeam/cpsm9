#ifndef UTILS_LSSS_H
#define UTILS_LSSS_H

#include <iostream>
#include <stack>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <regex>
#include <algorithm>
#include <cmath>

namespace cpabe {

enum Associativity { LEFT_ASSOC, RIGHT_ASSOC };

struct Node {
    int op_type;
    int left;
    int right;
};

class ExpressionParser {
private:
    std::vector<Node> expression;
    std::vector<std::vector<int>> M;
    std::vector<std::string> rho;
    std::vector<int> lambda;

    std::unordered_map<std::string, int> precedence = {{"and", 1}, {"or", 1}};
    std::unordered_map<std::string, Associativity> associativity = {{"and", RIGHT_ASSOC}, {"or", RIGHT_ASSOC}};

    void build_expression_tree(const std::vector<std::string>& postfix, std::unordered_map<std::string, int>& var_map);

public:
    std::vector<std::vector<int>> parse(std::string input);
    std::pair<std::vector<std::vector<int>>, std::vector<std::string>> convertToLSSS();
    void share(int secret);
    int reconstruct(std::vector<std::string> aSet);
};

}

#endif // UTILS_LSSS_H