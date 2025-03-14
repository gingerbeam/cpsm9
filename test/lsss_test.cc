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

TEST(LSSSTest, ReconstructTest1) {
    std::string policy = "(A and B and C) and (D or E or F) and (G and H and (I or J or K or L))";
    utils::LSSS parser(policy);
    // std::cout << "LSSS Matrix: \n";
    // parser.printMatrix();
    // std::cout << "LSSS Rho: \n";
    // parser.printRho();
    int *shares;
    parser.share(42, &shares);
    int res_s = parser.reconstruct(std::vector<std::string>{"A", "B", "C", "D", "G", "H", "I"}, shares);
    EXPECT_EQ(res_s, 42);
}

TEST(LSSSTest, ReconstructTest2) {
    std::string policy = "(A or B) and (C and D and (E or F)) and (G or H or (I and J))";
    utils::LSSS parser(policy);
    // std::cout << "LSSS Expression: \n";
    // parser.printExpression();
    // std::cout << "LSSS Matrix: \n";
    // parser.printMatrix();
    // std::cout << "LSSS Rho: \n";
    // parser.printRho();
    int *shares;
    parser.share(42, &shares);
    int res_s = parser.reconstruct(std::vector<std::string>{"A", "C", "D", "E", "G"}, shares);
    EXPECT_EQ(res_s, 42);
}

// TODO: priority of boolean operators
TEST(LSSSTest, ReconstructTest3) {
    std::string policy = "A or B and C and D and E or F and G or H or I and J";
    utils::LSSS parser(policy);
    // std::cout << "LSSS Expression: \n";
    // parser.printExpression();
    // std::cout << "LSSS Matrix: \n";
    // parser.printMatrix();
    // std::cout << "LSSS Rho: \n";
    // parser.printRho();
    int *shares;
    parser.share(42, &shares);
    int res_s = parser.reconstruct(std::vector<std::string>{"A"}, shares);
    EXPECT_EQ(res_s, 42);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}