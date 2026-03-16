/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Confidential Data defensive Framework is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan
 * PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
          * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
 * KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <iostream>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "rapidjson/document.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"

#include "cdf/modules/authorization/whitelist_authorization.h"

namespace cdf::test {

namespace rj = rapidjson;

class TestCDFAuthorization : public testing::Test {};

namespace {

inline void InitDocument(rj::Document &document)
{
    document.SetObject();
}

inline std::string GetDocumentContent(rj::Document &document)
{
    rj::StringBuffer buffer;
    rj::PrettyWriter<rj::StringBuffer> writer(buffer);
    document.Accept(writer);
    return buffer.GetString();
}

} // namespace

TEST_F(TestCDFAuthorization, test_whitelist_default)
{
    // GIVEN
    auto authorizor = WhitelistAuthorization();

    // WHEN
    auto ret = authorizor.CheckPermission("user1", "resource1", "GET");

    // THEN
    EXPECT_EQ(ret, AuthRC::FAILED);
}

TEST_F(TestCDFAuthorization, test_invalid_conf_format)
{
    // GIVEN
    auto authorizor = WhitelistAuthorization();

    const std::vector<std::string> testCases = {
        "{1,2, 3}",
        "{1,2, 3",
        "",
        R"({"test": "1111"})",
        R"([[{"test": "123"}]])",
        R"([{"user": 123}])",
        R"([{"user": "user1", "allow": "new"}])",
    };

    // WHEN and THEN
    for (const auto &c : testCases) {
        auto ret = authorizor.Initialize(c);
        EXPECT_EQ(ret, AuthRC::CONF_FORMAT_INVALID);
    }
}

TEST_F(TestCDFAuthorization, test_conflict_conf)
{
    // GIVEN
    auto authorizor = WhitelistAuthorization();

    // WHEN and THEN
    auto ret = authorizor.Initialize(
        R"([{"user": "user1", "allow": true}, {"user": "user1", "allow":
     false}])");
    EXPECT_EQ(ret, AuthRC::CONF_CONFLICT);
}

TEST_F(TestCDFAuthorization, test_whitelist_allowed)
{
    // GIVEN
    auto authorizor = WhitelistAuthorization();

    // WHEN and THEN
    rj::Document document;
    InitDocument(document);

    document.SetArray();
    rj::Value arrObject(rj::kArrayType);
    rj::Value user1(rj::kObjectType);
    rj::Value TrueObject(rj::kObjectType);
    user1.AddMember("user", "user1", document.GetAllocator());
    user1.AddMember("allow", rj::kTrueType, document.GetAllocator());
    document.PushBack(user1, document.GetAllocator());
    rj::Value user2(rj::kObjectType);
    user2.AddMember("user", "user2", document.GetAllocator());
    user2.AddMember("allow", rj::kFalseType, document.GetAllocator());
    document.PushBack(user2, document.GetAllocator());
    std::string conf = GetDocumentContent(document);

    auto ret = authorizor.Initialize(conf);
    EXPECT_EQ(ret, AuthRC::OK);
    EXPECT_EQ((int)authorizor.CheckPermission("", "resource1", "Get"), (int)(AuthRC::PARAM_ERROR));
    EXPECT_EQ((int)authorizor.CheckPermission("#$%^", "resource1", "Get"), (int)(AuthRC::FAILED));
    ret = authorizor.CheckPermission("user1", "resource1", "Get");
    EXPECT_EQ((int)ret, (int)AuthRC::OK);
    ret = authorizor.CheckPermission("user2", "resource1", "Get");
    EXPECT_EQ(ret, AuthRC::FAILED);
    ret = authorizor.CheckPermission("user3", "resource1", "Get");
    EXPECT_EQ(ret, AuthRC::FAILED);
    std::vector<std::string> principals;
    ret = authorizor.GetAllPrincipals(principals);
    EXPECT_EQ(ret, AuthRC::OK);
    int validPrincipalNumber = 2;
    EXPECT_EQ((size_t)validPrincipalNumber, principals.size());

    EXPECT_TRUE(principals[0] == "user1" || principals[1] == "user1");
    EXPECT_TRUE(principals[0] == "user2" || principals[1] == "user2");
    ret = authorizor.UnInitialize();
    EXPECT_EQ(ret, AuthRC::OK);
}

} // namespace cdf::test
