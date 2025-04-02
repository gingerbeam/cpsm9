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
#include <random>

#include <pbc/pbc.h>

namespace utils {

// used once for an expression
class ExprParser {
    std::vector<std::string> tokenize(const std::string& input);
    int traverse(int nodeIdx, int c, std::vector<int> &pVec);

public:
    struct Node {
        int op_type;
        int left;
        int right;
    };
    int leaf_count = 0;
    int tree_depth = 1;

    std::vector<Node> expression;
    std::unordered_map<std::string, int> atoi_map;
    std::unordered_map<int, std::string> itoa_map;
    std::vector<int> itor_map;
    std::vector<std::vector<int>> vecs;
    
    // initial expression & atoi_map & itoa_map
    ExprParser(std::string &input);
    ~ExprParser() {}
    // getter
    int get_l() { return leaf_count; }
    int get_n() { return tree_depth; }
    void printVecs() {
        for (auto &vec : vecs) {
            for (auto &v : vec) {
                printf("%d ", v);
            }
            printf("\n");
        }
    }
};

class LSSS {
private:
    pairing_t *pairing = nullptr;
    ExprParser *parser = nullptr;
    struct Policy {
        std::vector<std::vector<element_t*>> M;
        std::vector<std::string> rho;
    } policy;
    std::vector<int> S;

    int l;
    int n;

    void genLSSSPair();
    void solve(int row_n, int col_n, std::vector<element_t*> &omega);

public:
    LSSS(pairing_t *bp, std::string str);
    ~LSSS();

    std::vector<element_t*> share(element_t *secret);
    void reconstruct(std::vector<std::string> aSet, std::vector<element_t*> shares, element_t *result);
    std::unordered_map<int, element_t*> retriveOmega(std::vector<std::string> aSet);
    // getter
    int get_l() { return l; }
    int get_n() { return n; }
    // rho_map
    std::string rho_map(int idx) {
        if (idx < 0 || idx >= l) {
            throw std::runtime_error("idx out of range");
        } else {
            return policy.rho[idx];
        }
    }
    // find I
    std::vector<int> get_match(std::vector<std::string> aSet) {
        std::vector<int> res;
        for (size_t i = 0; i < l; ++i) {
            if (std::find(aSet.begin(), aSet.end(), (policy.rho)[i]) != aSet.end()) {
                res.push_back(i);
            }
        }
        return res;
    }
};

}

#endif // UTILS_LSSS_H