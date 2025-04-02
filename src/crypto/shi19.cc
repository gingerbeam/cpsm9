#include "crypto/shi19.h"

namespace crypto {


std::vector<std::string> split_expression(const std::string& expr) {
    std::vector<std::string> tokens;
    std::regex re(R"((\band\b)|(\bor\b)|(\bnot\b)|([A-Za-z0-9_]+)|([()]))");
    std::sregex_token_iterator it(expr.begin(), expr.end(), re, 0);
    std::sregex_token_iterator end;
    for (; it != end; ++it) {
        std::string token = *it;
        if (!token.empty()) {
            tokens.push_back(token);
        }
    }
    return tokens;
}

std::vector<std::string> replace_variables(const std::vector<std::string>& tokens, const std::map<std::string, bool>& var_map) {
    std::vector<std::string> replaced_tokens;
    for (const auto& token : tokens) {
        if (var_map.count(token)) {
            replaced_tokens.push_back(var_map.at(token) ? "true" : "false");
        } else {
            replaced_tokens.push_back(token);
        }
    }
    return replaced_tokens;
}

int get_priority(const std::string& op) {
    if (op == "not") return 3;
    else if (op == "and") return 2;
    else if (op == "or") return 1;
    else return 0; // 不是运算符，如括号
}

std::vector<std::string> infix_to_rpn(const std::vector<std::string>& tokens) {
    std::vector<std::string> output;
    std::stack<std::string> op_stack;
    for (const auto& token : tokens) {
        if (token == "true" || token == "false") {
            output.push_back(token);
        } else if (token == "(") {
            op_stack.push(token);
        } else if (token == ")") {
            while (!op_stack.empty() && op_stack.top() != "(") {
                output.push_back(op_stack.top());
                op_stack.pop();
            }
            if (!op_stack.empty() && op_stack.top() == "(") {
                op_stack.pop();
            }
        } else {
            while (!op_stack.empty() && 
                    get_priority(token) <= get_priority(op_stack.top())) {
                output.push_back(op_stack.top());
                op_stack.pop();
            }
            op_stack.push(token);
        }
    }
    while (!op_stack.empty()) {
        if (op_stack.top() == "(") {
            // 错误处理：括号不匹配
        }
        output.push_back(op_stack.top());
        op_stack.pop();
    }
    return output;
}

bool evaluate_rpn(const std::vector<std::string>& rpn_tokens) {
    std::stack<bool> st;
    for (const auto& token : rpn_tokens) {
        if (token == "true") {
            st.push(true);
        } else if (token == "false") {
            st.push(false);
        } else {
            if (token == "not") {
                bool a = st.top(); st.pop();
                st.push(!a);
            } else if (token == "and") {
                bool b = st.top(); st.pop();
                bool a = st.top(); st.pop();
                st.push(a && b);
            } else if (token == "or") {
                bool b = st.top(); st.pop();
                bool a = st.top(); st.pop();
                st.push(a || b);
            }
        }
    }
    return st.top();
}

std::vector<std::vector<std::string>> get_access_structure(const std::string& expr, const std::vector<std::string>& U) {
    std::map<std::string, int> var_indices;
    for (size_t i = 0; i < U.size(); ++i) {
        var_indices[U[i]] = i;
    }
    size_t n = U.size();
    std::vector<std::vector<std::string>> result;
    for (int mask = 0; mask < (1 << n); ++mask) {
        std::map<std::string, bool> current_vars;
        for (size_t i = 0; i < n; ++i) {
            current_vars[U[i]] = (mask & (1 << i)) != 0;
        }
        std::vector<std::string> tokens = split_expression(expr);
        std::vector<std::string> replaced_tokens = replace_variables(tokens, current_vars);
        std::vector<std::string> rpn = infix_to_rpn(replaced_tokens);
        bool res = evaluate_rpn(rpn);
        if (res) {
            std::vector<std::string> valid_vars;
            for (const auto& var : U) {
                if (current_vars[var]) {
                    valid_vars.push_back(var);
                }
            }
            result.push_back(valid_vars);
        }
    }
    return result;
}
    
std::string shi19::set_to_id(std::vector<std::string> &attrs) {
    std::string result;
    for (const auto& user : user_set) {
        if (std::find(attrs.begin(), attrs.end(), user) != attrs.end()) {
            result += '1';
        } else {
            result += '0';
        }
    }
    return result;
}

shi19::shi19(std::string &param, std::vector<std::string> U) : besm9(param, U) {
    // access_structure = getAccessStructure(U);
}

void shi19::shi19Keygen(std::vector<std::string> &attrs, secretkey *sk) {
    auto id = set_to_id(attrs);
    kemsm9::Keygen(id, sk);
}

void shi19::shi19Encrypt(plaintext &ptx, std::string policy, abe_ciphertext *ctx) {
    std::vector<std::vector<std::string>> as = get_access_structure(policy, besm9::user_set);
    std::vector<std::string> ids(as.size());
    for (int i = 0; i < as.size(); ++i) {
        auto id = set_to_id(as[i]);
        ids[i] = id;
    }
    besm9::BEncrypt(ptx, ids, ctx); 
}
void shi19::shi19Encrypt(plaintext &ptx, std::vector<std::vector<std::string>> &as, abe_ciphertext *ctx) {
    std::vector<std::string> ids(as.size());
    for (int i = 0; i < as.size(); ++i) {
        auto id = set_to_id(as[i]);
        ids[i] = id;
    }
    besm9::BEncrypt(ptx, ids, ctx);
}

void shi19::shi19Decrypt(abe_ciphertext *ctxs, std::vector<std::string> &attrs, secretkey *sk, plaintext *ptx) {
    auto id = set_to_id(attrs);
    besm9::BDecrypt(ctxs, sk, ptx);
}

}