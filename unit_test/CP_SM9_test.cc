#include <gtest/gtest.h>
#include <scheme/CP_SM9.h>

/* 测试 LSSS 策略满足性判断功能
 * 测试场景：
 * 1. 当属性集合完全匹配策略要求时返回true
 * 2. 当属性集合不满足策略要求时返回false
 */
TEST(LSSS_PolicyTest, SatisfiesTest) {
    // 创建策略对象并初始化"attr1 AND attr2"逻辑表达式
    LSSS_Policy policy("attr1 AND attr2");
    /* 测试用例1：提供全部必需属性 */
    std::vector<std::string> attributes = {"attr1", "attr2"};
    EXPECT_TRUE(policy.satisfies(attributes));

    attributes = {"attr1"};
    EXPECT_FALSE(policy.satisfies(attributes));
}

TEST(LSSS_PolicyTest, DoesNotSatisfyTest) {
    LSSS_Policy policy("attr1 AND attr2");
    std::vector<std::string> attributes = {"attr3"};
    EXPECT_FALSE(policy.satisfies(attributes));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}