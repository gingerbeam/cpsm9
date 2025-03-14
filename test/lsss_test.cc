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

TEST(LSSSTest, ConvertMatrixTest) {
    std::string policy = "(A and B and C) and (D or E or F) and (G and H and (I or J or K or L))";
    utils::LSSS parser(policy);
    parser.share(42);
    int res_s = parser.reconstruct(std::vector<std::string>{"A", "B", "C", "D", "G", "H", "I"});
    EXPECT_EQ(res_s, 42);
}

TEST(LSSSTest, ReconstructTest) {
    std::string policy = "A or (B and C or A)";
    utils::LSSS parser(policy);
    parser.share(42);
    int res_s = parser.reconstruct(std::vector<std::string>{"A", "B", "C"});
    EXPECT_EQ(res_s, 42);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}