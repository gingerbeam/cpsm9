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
    std::vector<int> lambda;

    std::unordered_map<std::string, int> precedence = {{"and", 1}, {"or", 1}};
    std::unordered_map<std::string, int> associativity = {{"and", 1}, {"or", 1}};

    // parse expression string to expression tree
    void parse(std::string& input);
    // convert expression tree to LSSS policies
    std::pair<std::vector<std::vector<int>>, std::vector<std::string>> convertToLSSS();
    void generateVectors(int nodeIndex, std::vector<int> parentVector, int& c, std::vector<std::vector<int>>& matrix, std::vector<std::string>& mapping, const std::vector<Node>& nodes);

public:
    LSSS(std::string policy);
    ~LSSS();
    
    void share(int secret);
    int reconstruct(std::vector<std::string> aSet);
};

}

#endif // UTILS_LSSS_H