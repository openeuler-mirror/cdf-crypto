/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Confidential Data defensive Framework is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan
 * PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
 * KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <filesystem>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

#include "gtest/gtest.h"

#include "cdf/modules/key_management/openbao/openbao_utils.h"
#include "temp_directory.h"

namespace cdf::test {

class OpenbaoUtilsTest : public ::testing::Test {};

TEST_F(OpenbaoUtilsTest, GetJsonFieldAsStr_ValidJson)
{
    std::string jsonStr = R"({"data":{"keys":{"key1":"value1","key2":"value2"}}})";
    auto result = GetJsonFieldAsStr(jsonStr);
    EXPECT_EQ(result, "value2");
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldAsStr_InvalidJson)
{
    std::string jsonStr = "invalid json";
    auto result = GetJsonFieldAsStr(jsonStr);
    EXPECT_TRUE(result.empty());
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldAsStr_EmptyJson)
{
    std::string jsonStr = "{}";
    auto result = GetJsonFieldAsStr(jsonStr);
    EXPECT_TRUE(result.empty());
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldAsStr_MissingDataField)
{
    std::string jsonStr = R"({"keys":{"key1":"value1"}})";
    auto result = GetJsonFieldAsStr(jsonStr);
    EXPECT_TRUE(result.empty());
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldAsStr_MissingKeysField)
{
    std::string jsonStr = R"({"data":{"other":"value"}})";
    auto result = GetJsonFieldAsStr(jsonStr);
    EXPECT_TRUE(result.empty());
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldAsStr_NonStringValue)
{
    std::string jsonStr = R"({"data":{"keys":{"key1":123}}})";
    auto result = GetJsonFieldAsStr(jsonStr);
    EXPECT_TRUE(result.empty());
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldMaxInt_ValidJson)
{
    std::string jsonStr = R"({"data":{"keys":{"key1":1,"key2":5,"key3":3}}})";
    auto result = GetJsonFieldMaxInt(jsonStr);
    EXPECT_EQ(result, 5);
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldMaxInt_InvalidJson)
{
    std::string jsonStr = "invalid json";
    auto result = GetJsonFieldMaxInt(jsonStr);
    EXPECT_EQ(result, -1);
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldMaxInt_EmptyJson)
{
    std::string jsonStr = "{}";
    auto result = GetJsonFieldMaxInt(jsonStr);
    EXPECT_EQ(result, -1);
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldMaxInt_NonIntValue)
{
    std::string jsonStr = R"({"data":{"keys":{"key1":"not_an_int"}}})";
    auto result = GetJsonFieldMaxInt(jsonStr);
    EXPECT_EQ(result, -1);
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldMaxInt_SingleValue)
{
    std::string jsonStr = R"({"data":{"keys":{"key1":42}}})";
    auto result = GetJsonFieldMaxInt(jsonStr);
    EXPECT_EQ(result, 42);
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldIntPairVec_ValidJson)
{
    std::string jsonStr = R"(["CDF1_Key001","CDF1_Key002","CDF2_Key001"])";
    std::vector<std::pair<uint32_t, uint32_t>> result;
    auto rc = GetJsonFieldIntPairVec(jsonStr, result);
    EXPECT_EQ(rc, KeyManagerRC::OK);
    EXPECT_EQ(result.size(), 3u);
    EXPECT_EQ(result[0], std::make_pair(1u, 1u));
    EXPECT_EQ(result[1], std::make_pair(1u, 2u));
    EXPECT_EQ(result[2], std::make_pair(2u, 1u));
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldIntPairVec_InvalidJson)
{
    std::string jsonStr = "invalid json";
    std::vector<std::pair<uint32_t, uint32_t>> result;
    auto rc = GetJsonFieldIntPairVec(jsonStr, result);
    EXPECT_EQ(rc, KeyManagerRC::ERROR);
    EXPECT_TRUE(result.empty());
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldIntPairVec_EmptyArray)
{
    std::string jsonStr = "[]";
    std::vector<std::pair<uint32_t, uint32_t>> result;
    auto rc = GetJsonFieldIntPairVec(jsonStr, result);
    EXPECT_EQ(rc, KeyManagerRC::ERROR);
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldIntPairVec_NotArray)
{
    std::string jsonStr = R"({"key":"value"})";
    std::vector<std::pair<uint32_t, uint32_t>> result;
    auto rc = GetJsonFieldIntPairVec(jsonStr, result);
    EXPECT_EQ(rc, KeyManagerRC::ERROR);
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldIntPairVec_InvalidFormat)
{
    std::string jsonStr = R"(["invalid_format"])";
    std::vector<std::pair<uint32_t, uint32_t>> result;
    auto rc = GetJsonFieldIntPairVec(jsonStr, result);
    EXPECT_EQ(rc, KeyManagerRC::ERROR);
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldIntPairVec_NonStringElement)
{
    std::string jsonStr = R"([123, "CDF1_Key001"])";
    std::vector<std::pair<uint32_t, uint32_t>> result;
    auto rc = GetJsonFieldIntPairVec(jsonStr, result);
    EXPECT_EQ(rc, KeyManagerRC::ERROR);
}

TEST_F(OpenbaoUtilsTest, RejectsNonObjectRootAndEmptyKeys)
{
    EXPECT_TRUE(GetJsonFieldAsStr(R"([])").empty());
    EXPECT_TRUE(GetJsonFieldAsStr(R"({"data":{"keys":{}}})").empty());
    EXPECT_EQ(GetJsonFieldMaxInt(R"([])"), -1);
    EXPECT_EQ(GetJsonFieldMaxInt(R"({"data":{"keys":{}}})"), -1);
}

TEST_F(OpenbaoUtilsTest, RejectsMixedIntegerAndStringKeys)
{
    EXPECT_EQ(GetJsonFieldMaxInt(R"({"data":{"keys":{"first":7,"second":"8"}}})"), -1);
}

TEST_F(OpenbaoUtilsTest, RejectsNonNumericDomainAndKey)
{
    std::vector<std::pair<uint32_t, uint32_t>> result;
    EXPECT_EQ(GetJsonFieldIntPairVec(R"(["CDFx_Key001"])", result), KeyManagerRC::ERROR);
    EXPECT_TRUE(result.empty());

    EXPECT_EQ(GetJsonFieldIntPairVec(R"(["CDF1_Keyx"])", result), KeyManagerRC::ERROR);
    EXPECT_TRUE(result.empty());
}

TEST_F(OpenbaoUtilsTest, SkipsElementsWithoutSeparatorAndKeepsExactPairs)
{
    std::vector<std::pair<uint32_t, uint32_t>> result;
    ASSERT_EQ(GetJsonFieldIntPairVec(R"(["CDF1Key001","CDF2_Key003"])", result), KeyManagerRC::OK);
    EXPECT_EQ(result, (std::vector<std::pair<uint32_t, uint32_t>>{{2u, 3u}}));
}

namespace {

std::filesystem::path CreateCommandScript(const TempDirectory &temp)
{
    auto script = temp.Path() / "bao-test";
    std::ofstream output(script);
    output << R"(#!/bin/sh
if [ "$1" = login ]; then
    read token
    [ "$token" = good-token ] || exit 3
    exit 0
fi
case "$1" in
    success) echo '{"data":{"keys":{"k":1}}}'; exit 0 ;;
    message-error) echo 'Error: rejected'; exit 0 ;;
    vault-empty) echo '{}'; exit 2 ;;
    *) echo 'command failed'; exit 4 ;;
esac
)";
    output.close();
    std::filesystem::permissions(script, std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace);
    return script;
}

std::string Command(const std::filesystem::path &script, const std::string &argument)
{
    return script.string() + " " + argument;
}

} // namespace

TEST(OpenbaoCommandTest, ReturnsSuccessfulCommandOutput)
{
    TempDirectory temp;
    auto script = CreateCommandScript(temp);

    auto [rc, output] = RunCommandAndGetResult(script.string(), "good-token", Command(script, "success"));
    EXPECT_EQ(rc, KeyManagerRC::OK);
    EXPECT_EQ(output, "{\"data\":{\"keys\":{\"k\":1}}}\n");
    EXPECT_EQ(RunCommandAndCheck(script.string(), "good-token", Command(script, "success")), KeyManagerRC::OK);
}

TEST(OpenbaoCommandTest, RejectsErrorTextAndPreservesOutput)
{
    TempDirectory temp;
    auto script = CreateCommandScript(temp);

    auto [rc, output] = RunCommandAndGetResult(script.string(), "good-token", Command(script, "message-error"));
    EXPECT_EQ(rc, KeyManagerRC::ERROR);
    EXPECT_EQ(output, "Error: rejected\n");
    EXPECT_EQ(RunCommandAndCheck(script.string(), "good-token", Command(script, "message-error")),
        KeyManagerRC::ERROR);
}

TEST(OpenbaoCommandTest, TreatsVaultEmptyListAsSuccess)
{
    TempDirectory temp;
    auto script = CreateCommandScript(temp);

    auto [rc, output] = RunCommandAndGetResult(script.string(), "good-token", Command(script, "vault-empty"));
    EXPECT_EQ(rc, KeyManagerRC::OK);
    EXPECT_EQ(output, "{}\n");
}

TEST(OpenbaoCommandTest, RejectsBadOrEmptyAccessToken)
{
    TempDirectory temp;
    auto script = CreateCommandScript(temp);

    auto [badRc, badOutput] = RunCommandAndGetResult(script.string(), "bad-token", Command(script, "success"));
    EXPECT_EQ(badRc, KeyManagerRC::ERROR);
    EXPECT_TRUE(badOutput.empty());

    auto [emptyRc, emptyOutput] = RunCommandAndGetResult(script.string(), "", Command(script, "success"));
    EXPECT_EQ(emptyRc, KeyManagerRC::ERROR);
    EXPECT_TRUE(emptyOutput.empty());
}

TEST(OpenbaoCommandTest, RejectsEmptyCommandAndMissingExecutable)
{
    TempDirectory temp;
    auto script = CreateCommandScript(temp);

    auto [emptyRc, emptyOutput] = RunCommandAndGetResult(script.string(), "good-token", "");
    EXPECT_EQ(emptyRc, KeyManagerRC::ERROR);
    EXPECT_TRUE(emptyOutput.empty());

    auto missing = temp.Path() / "missing";
    auto [missingRc, missingOutput] =
        RunCommandAndGetResult(missing.string(), "good-token", Command(missing, "success"));
    EXPECT_EQ(missingRc, KeyManagerRC::ERROR);
    EXPECT_TRUE(missingOutput.empty());
}

} // namespace cdf::test
