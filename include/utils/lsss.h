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

namespace utils {

std::vector<std::string> tokenize(const std::string& input);

class LSSS {
private:
    struct Node {
        int op_type;
        int left;
        int right;
    };
    std::vector<Node> expression;
    std::vector<std::vector<int>> M;
    std::vector<std::string> rho;

    // parse expression string to expression tree
    void parse(std::string& input);
    // convert expression tree to LSSS policies
    std::pair<std::vector<std::vector<int>>, std::vector<std::string>> convertToLSSS();
    void generateVectors(int nodeIndex, std::vector<int> parentVector, int c, std::vector<std::vector<int>>& matrix, std::vector<std::string>& mapping, const std::vector<Node>& nodes);

public:
    LSSS(std::string policy);
    ~LSSS();

    void share(int secret, int **shares);
    int reconstruct(std::vector<std::string> aSet, int* shares);

    void printMatrix() {
        for (int i = 0; i < M.size(); i++) {
            for (int j = 0; j < M[i].size(); j++) {
                std::cout << M[i][j] << " ";
            }
            std::cout << std::endl;
        }
    }

    void printRho() {
        for (int i = 0; i < rho.size(); i++) {
            std::cout << rho[i] << " ";
        }
        std::cout << std::endl;
    }

    void printExpression() {
        std::vector<std::vector<int>> res;
        for (const auto& node : expression) {
            std::vector<int> temp;
            temp.push_back(node.op_type);
            temp.push_back(node.left);
            temp.push_back(node.right);
            res.push_back(temp);
        }
        for (const auto& row : res) {
            for (const auto& col : row) {
                std::cout << col << " ";
            }
            std::cout << std::endl;
        }
    }
};

}

#endif // UTILS_LSSS_H