#include "utils/lsss.h"
#include <gtest/gtest.h>
#include <algorithm>

bool isMatrixEqualIgnoreOrder(const std::vector<std::vector<int>>& matrix1, const std::vector<std::vector<int>>& matrix2) {
    if (matrix1.size() != matrix2.size()) return false;
    auto sorted1 = matrix1;
    auto sorted2 = matrix2;
    std::sort(sorted1.begin(), sorted1.end());
    std::sort(sorted2.begin(), sorted2.end());
    return sorted1 == sorted2;
}

TEST(LSSSTest, ParsePolicyTest1) {
    ExpressionParser parser;
    std::string policy = "A and B and C";
    std::vector<std::vector<int>> matrix = parser.parse(policy);
    std::vector<std::vector<int>> expected = {
        {0, -1, 1},
        {0, -2, -3}
    };
    EXPECT_TRUE(isMatrixEqualIgnoreOrder(matrix, expected));
}

TEST(LSSSTest, ParsePolicyTest2) {
    ExpressionParser parser;
    std::string policy = "A or (B and C or A)";
    std::vector<std::vector<int>> matrix = parser.parse(policy);
    std::vector<std::vector<int>> expected = {
        {1, -1, 1}, // 根节点为and门，左指向下标1的and门，右指向下标2的and门
        {0, -2, 2}, // 左and门，操作数A（-1）、B（-2）
        {1, -3, -1} // 右or门，操作数C（-3）、A（-1）
    };
    EXPECT_TRUE(isMatrixEqualIgnoreOrder(matrix, expected));
}

TEST(LSSSTest, ConvertMatrixTest1) {
    ExpressionParser parser;
    std::string policy = "A and B and C";
    std::vector<std::vector<int>> matrix = parser.parse(policy);
    std::pair<std::vector<std::vector<int>>, std::vector<std::string>> res = parser.convertToLSSS();
    std::vector<std::vector<int>> expected = {
        {1, 1, 0},
        {0, -1, 1},
        {0, 0, -1}
    };
    EXPECT_TRUE(isMatrixEqualIgnoreOrder(res.first, expected));
}

TEST(LSSSTest, ConvertMatrixTest2) {
    ExpressionParser parser;
    std::string policy = "A and B or C";
    std::vector<std::vector<int>> matrix = parser.parse(policy);
    std::pair<std::vector<std::vector<int>>, std::vector<std::string>> res = parser.convertToLSSS();
    std::vector<std::vector<int>> expected = {
        {1, 1},
        {0, -1},
        {0, -1}
    };
    EXPECT_TRUE(isMatrixEqualIgnoreOrder(res.first, expected));
}

TEST(LSSSTest, ConvertMatrixTest3) {
    ExpressionParser parser;
    std::string policy = "A or (B and C or A)";
    std::vector<std::vector<int>> matrix = parser.parse(policy);
    std::pair<std::vector<std::vector<int>>, std::vector<std::string>> res = parser.convertToLSSS();
    std::vector<std::vector<int>> expected = {
        {1, 0},
        {1, 1},
        {0, -1},
        {0, -1}
    };
    EXPECT_TRUE(isMatrixEqualIgnoreOrder(res.first, expected));
}

TEST(LSSSTest, ReconstructTest1) {
    ExpressionParser parser;
    std::string policy = "A or (B and C or A)";
    std::vector<std::vector<int>> matrix = parser.parse(policy);
    std::pair<std::vector<std::vector<int>>, std::vector<std::string>> res = parser.convertToLSSS();
    parser.share(42);
    int res_s = parser.reconstruct(std::vector<std::string>{"A", "B", "C"});
    EXPECT_EQ(res_s, 42);
}

TEST(LSSSTest, ReconstructTest2) {
    ExpressionParser parser;
    std::string policy = "(A and B and C) and (D or E or F) and (G and H and (I or J or K or L))";
    std::vector<std::vector<int>> matrix = parser.parse(policy);
    std::pair<std::vector<std::vector<int>>, std::vector<std::string>> res = parser.convertToLSSS();
    parser.share(42);
    int res_s = parser.reconstruct(std::vector<std::string>{"A", "B", "C", "D", "G", "H", "I"});
    // std::cout << res_s << std::endl;
    EXPECT_EQ(res_s, 42);
}

TEST(LSSSTest, ReconstructTest3) {
    ExpressionParser parser;
    std::string policy = "A or (B and C or A) and D";
    std::vector<std::vector<int>> matrix = parser.parse(policy);
    std::pair<std::vector<std::vector<int>>, std::vector<std::string>> res = parser.convertToLSSS();
    parser.share(42);
    EXPECT_ANY_THROW(parser.reconstruct(std::vector<std::string>{"B", "C"}));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}