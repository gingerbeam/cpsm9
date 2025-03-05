#ifndef CP_SM9_H
#define CP_SM9_H

#ifndef IMPORT_ELEMENTLIST
#define IMPORT_ELEMENTLIST
#include "base/ElementList.h"
#endif //IMPORT_ELEMENTLIST

#ifndef IMPORT_UTIL_FUNC
#define IMPORT_UTIL_FUNC
#include "utils/func.h"
#endif //IMPORT_UTIL_FUNC

class LSSS_Policy {
public:
    LSSS_Policy(const std::string& policy);
    ~LSSS_Policy();
    bool satisfies(const std::vector<std::string>& attributes) const;

private:
    std::string policy;
    // 其他私有成员和方法
};

class CP_SM9 {
    protected:
        element_t *G1, *G2; // 椭圆曲线上的群元素
        element_t master_key; // 主密钥
        element_t public_key; // 公钥
        std::vector<std::string> attributes; // 用户属性集合

    public:
        CP_SM9(); // 构造函数
        ~CP_SM9(); // 析构函数

        void initialize(); // 初始化系统参数
        void generate_master_key(); // 生成主密钥
        void generate_user_key(const std::vector<std::string>& user_attributes); // 生成用户密钥
        void encrypt(const std::string& policy); // 加密数据
        bool decrypt(const std::string& ciphertext, const std::vector<std::string>& user_attributes); // 解密数据
};

#endif